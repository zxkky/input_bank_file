    const express = require('express');
    const path = require('path');
    const bodyParser = require('body-parser');
    const bcrypt = require('bcrypt');
    const session = require('express-session');
    const multer = require('multer');
    const connection = require('./config/database');
    const PDFDocument = require('pdfkit');  
    const moment = require('moment');
    const fs = require('fs');

    const app = express();
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(bodyParser.json());


    app.use(session({
        secret: 'dontolodon', 
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false } 
    }));

    app.set('view engine', 'ejs');
    app.set('views', path.join(__dirname, 'views'));
    app.use(express.static(path.join(__dirname, 'uploads')));
    app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

    // Konfigurasi multer untuk pengunggahan foto pengguna
    const storage = multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, 'uploads/'); // Simpan file di direktori uploads
        },
        filename: (req, file, cb) => {
            cb(null, `${Date.now()}-${file.originalname}`); // Ubah nama file untuk menghindari konflik
        }
    });
    const upload = multer({ storage: storage });

    // Middleware untuk memeriksa apakah pengguna terautentikasi
    function checkAuthenticated(req, res, next) {
        if (req.session.isAuthenticated) {
            return next(); // Lanjutkan jika pengguna masuk
        }
        res.redirect('/login'); // Alihkan ke halaman login jika tidak masuk
    }

    // Middleware untuk memeriksa peran pengguna
    function checkRole(roles) {
        return (req, res, next) => {
            if (!req.user || !req.user.role) {
                return res.status(401).send('Unauthorized');
            }
    
            if (!roles.includes(req.user.role)) {
                return res.status(403).send('Forbidden');
            }
    
            next();
        };
    }

    // Rute
    app.get('/', (req, res) => {
        res.render('index');
    });

    app.get('/admin/settings', (req, res) => {
        res.render('admin/settings');
    });
 
    app.get('/admin/edit_user', (req, res) => {
        res.render('admin/edit_user');
    });
    app.get('/login', (req, res) => {
        res.render('login');
    });

    app.post('/login', async (req, res) => {
        const { username, password } = req.body;

        const query = `
            SELECT u.*, r.role_name 
            FROM users u 
            JOIN roles r ON u.role_id = r.id 
            WHERE username = ?
        `;
        
        connection.query(query, [username], async (err, results) => {
            if (err) {
                console.error('Error fetching user:', err);
                return res.status(500).send('Error fetching user');
            }

            if (results.length === 0) {
                return res.status(400).send('User not found');
            }

            const user = results[0];
            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                return res.status(400).send('Incorrect password');
            }

            // Atur data sesi
            req.session.isAuthenticated = true;
            req.session.userId = user.id;
            req.session.userRole = user.role_name; // Simpan peran pengguna untuk digunakan nanti

            // Perbarui status pengguna menjadi online setelah login
            const updateQuery = 'UPDATE users SET is_online = TRUE WHERE id = ?';
            connection.query(updateQuery, [user.id], (err) => {
                if (err) {
                    console.error('Error updating user status:', err);
                    return res.status(500).send('Error updating user status');
                }
                res.redirect('/home');
            });
        });
    });
    app.use('/views', express.static('views'));

    app.post('/logout', (req, res) => {
        const userId = req.session.userId;

        const query = 'UPDATE users SET is_online = FALSE WHERE id = ?';
        connection.query(query, [userId], (err) => {
            if (err) {
                console.error('Error updating user status:', err);
                return res.status(500).send('Error updating user status');
            }

            // Hancurkan sesi pengguna
            req.session.destroy(err => {
                if (err) {
                    return res.status(500).send('Error logging out');
                }
                res.redirect('/login');
            });
        });
    });

    // Halaman beranda - dapat diakses setelah login
    app.get('/home', checkAuthenticated, (req, res) => {
        const userId = req.session.userId;

        const query = 'SELECT photo FROM users WHERE id = ?';
        connection.query(query, [userId], (err, results) => {
            if (err || results.length === 0) {
                console.error('Error fetching user photo:', err);
                return res.status(500).send('Error fetching user photo');
            }

            let userProfilePhoto = results[0].photo.replace(/\\/g, '/'); // Ganti backslash
            const userRole = req.session.userRole;

            console.log(userProfilePhoto); // Debug output

            res.render('home', { userProfilePhoto, userRole });
            console.log(userProfilePhoto); // Debug output
        });
    });

    // Rute untuk mengunggah dan menampilkan file untuk Admin dan Pengguna
app.get('/file', checkAuthenticated, (req, res) => {
    const search = req.query.search || '';
    const formattedSearch = `%${search}%`;

    // Mendapatkan kolom sorting dari query string, dengan default 'created_at'
    const sortBy = req.query.sort_by || 'created_at';
    const order = req.query.order === 'asc' ? 'ASC' : 'DESC'; // Default ke 'DESC'

    // Menjaga kolom sorting agar aman dari SQL Injection
    const allowedColumns = ['borrower_name', 'file_number', 'created_at', 'loan_amount', 'room_number', 'safe_number', 'shelf_number', 'file_sequence','rek'];
    if (!allowedColumns.includes(sortBy)) {
        return res.status(400).send('Invalid sort column');
    }

    // Query dengan penyortiran dinamis
    const query = `
        SELECT * 
        FROM bank_files 
        WHERE borrower_name LIKE ? OR file_number LIKE ? 
        ORDER BY 
            CASE 
                WHEN room_number REGEXP '^[0-9]' THEN CAST(room_number AS UNSIGNED)
                ELSE NULL 
            END ASC,
            CASE 
                WHEN safe_number REGEXP '^[A-Za-z]' THEN safe_number
                ELSE NULL 
            END ASC,
            CASE 
                WHEN shelf_number REGEXP '^[0-9]' THEN CAST(shelf_number AS UNSIGNED)
                ELSE NULL 
            END ASC,
            CASE 
                WHEN file_sequence REGEXP '^[0-9]' THEN CAST(file_sequence AS UNSIGNED)
                ELSE NULL 
            END ASC,
            ${sortBy} ${order}
    `;

    connection.query(query, [formattedSearch, formattedSearch], (err, results) => {
        if (err) {
            console.error('Error fetching files:', err);
            return res.status(500).send('Error fetching files');
        }

        results.forEach(file => {
            file.date = new Date(file.date).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
            file.created_at = new Date(file.created_at).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
        });

        res.render('file', { files: results, sortBy, order });
    });
});

    // Rute sukses unggahan untuk Admin
    app.get('/upload-success', checkAuthenticated, checkRole(['Admin', 'Super Admin']), (req, res) => {
        res.render('upload', { success: true });
    });

    // Rute unggahan untuk Admin
    // Menangani pengunggahan file
    app.post('/upload', checkAuthenticated, checkRole(['Admin', 'Super Admin']), (req, res) => {
        const { room_number, safe_number, shelf_number, file_sequence, date, loan_amount, borrower_name, marketing, rek } = req.body;
    
        // Get user ID from session
        const userId = req.session.userId; 
    
        console.log('User ID:', userId);  // Verify that the user ID is correct
    
        // Construct the SQL query for insertion
        const query = 
           ` INSERT INTO bank_files 
            (room_number, safe_number, shelf_number, file_sequence, date, loan_amount, borrower_name, marketing, rek, uploaded_by) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ;
        const values = [room_number, safe_number, shelf_number, file_sequence, date, loan_amount, borrower_name, marketing, rek, userId];
    
        // Execute the query to insert data into the database
        connection.query(query, values, (err) => {
            if (err) {
                console.error('Error inserting data:', err);
                return res.status(500).send('Error inserting data');
            }
            res.redirect('/upload-success');
        });
    });
   
    app.get('/admin_file', checkAuthenticated, (req, res) => {
        const search = req.query.search || '';
        const formattedSearch = `%${search}%`;
    
        // Get the sort column and order from query params
        const sortBy = req.query.sort_by || 'created_at';
        const order = req.query.order === 'asc' ? 'ASC' : 'DESC'; // Default to 'DESC'
    
        // Prevent SQL injection by allowing only specific columns for sorting
        const allowedColumns = ['borrower_name', 'file_number', 'created_at', 'loan_amount', 'room_number', 'safe_number', 'shelf_number', 'file_sequence'];
        if (!allowedColumns.includes(sortBy)) {
            return res.status(400).send('Invalid sort column');
        }
    
        // SQL query with JOIN to get the username of the uploader
        const query = `
            SELECT bf.*, u.username AS uploaded_by
            FROM bank_files bf
            JOIN users u ON bf.uploaded_by = u.id
            WHERE bf.borrower_name LIKE ? OR bf.file_number LIKE ?
            ORDER BY 
                CASE 
                    WHEN bf.room_number REGEXP '^[0-9]' THEN CAST(bf.room_number AS UNSIGNED)
                    ELSE NULL 
                END ASC,
                CASE 
                    WHEN bf.safe_number REGEXP '^[A-Za-z]' THEN bf.safe_number
                    ELSE NULL 
                END ASC,
                CASE 
                    WHEN bf.shelf_number REGEXP '^[0-9]' THEN CAST(bf.shelf_number AS UNSIGNED)
                    ELSE NULL 
                END ASC,
                CASE 
                    WHEN bf.file_sequence REGEXP '^[0-9]' THEN CAST(bf.file_sequence AS UNSIGNED)
                    ELSE NULL 
                END ASC,
                ${sortBy} ${order}
        `;
    
        connection.query(query, [formattedSearch, formattedSearch], (err, results) => {
            if (err) {
                console.error('Error fetching files:', err);
                return res.status(500).send('Error fetching files');
            }
    
            // Format dates
            results.forEach(file => {
                file.date = new Date(file.date).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric'
                });
                file.created_at = new Date(file.created_at).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric'
                });
            });
    
            // Render the view and pass the results along with sorting options
            res.render('admin/admin_file', { files: results, sortBy, order });
        });
    });
    
    // Rute untuk mengedit file
app.post('/admin/edit-file/:fileId', checkAuthenticated, checkRole(['Admin', 'Super Admin']), (req, res) => {
        const { fileId } = req.params;
        const { rek, room_number, safe_number, shelf_number, file_sequence, date, loan_amount, borrower_name, marketing } = req.body;
    
        const query = `
            UPDATE bank_files 
            SET rek = ?, room_number = ?, safe_number = ?, shelf_number = ?, file_sequence = ?, date = ?, loan_amount = ?, borrower_name = ?, marketing = ?
            WHERE id = ?
        `;
    
        connection.query(query, [rek, room_number, safe_number, shelf_number, file_sequence, date, loan_amount, borrower_name, marketing, fileId], (err, results) => {
            if (err) {
                console.error('Error updating file:', err);
                return res.status(500).send('Error updating file');
            }
    
            res.redirect('/admin_file'); // Redirect to the files list page after updating
        });
    });
    
    
    
// Rute untuk menghapus file
app.post('/admin/delete-file/:fileId', checkAuthenticated, checkRole(['Admin', 'Super Admin']), (req, res) => {
    const { fileId } = req.params;
    console.log('Deleting file with ID:', fileId);

    const query = 'DELETE FROM bank_files WHERE id = ?';
    connection.query(query, [fileId], (err) => {
        if (err) {
            console.error('Error deleting file:', err);
            return res.status(500).send('Error deleting file');
        }

        console.log('File deleted successfully. Redirecting to /admin/admin_file');
        res.redirect('/admin_file');
    });
});


// Rute untuk mendownload file

app.get('/admin/edit-file/:fileId', checkAuthenticated, checkRole(['Admin', 'Super Admin']), (req, res) => {
    const { fileId } = req.params;

    const query = 'SELECT * FROM bank_files WHERE id = ?';
    connection.query(query, [fileId], (err, results) => {
        if (err) {
            console.error('Error fetching file:', err);
            return res.status(500).send('Error fetching file');
        }

        if (results.length === 0) {
            return res.status(404).send('File not found');
        }

        // Pass the file data to the edit form
        const file = results[0];
        res.render('admin/edit_file', { file });
    });
});

app.get('/admin', checkAuthenticated, checkRole(['Admin', 'Super Admin']), (req, res) => {
    const usersQuery = 'SELECT username FROM users WHERE id = ?'; // Query untuk mengambil nama pengguna berdasarkan id yang sedang login
    const totalUsersQuery = 'SELECT COUNT(*) AS totalUsers FROM users';
    const totalFileQuery = 'SELECT COUNT(*) AS totalFile FROM bank_files';
    const totalOnlineQuery = 'SELECT COUNT(*) AS totalOnline FROM users WHERE is_online = 1';
    const grafikQuery = `
    SELECT 
    DATE(created_at) AS upload_date, 
    COUNT(*) AS file_count 
FROM 
    bank_files
GROUP BY 
    DATE(created_at)
ORDER BY 
    upload_date ASC`
;
    
    connection.query(totalUsersQuery, (err, totalUsersResult) => {
        if (err) {
            console.error('Error fetching total users:', err);
            return res.status(500).send('Error fetching total users');
        }
        const totalUsers = totalUsersResult[0].totalUsers;
    
        connection.query(totalOnlineQuery, (err, totalOnlineResult) => {
            if (err) {
                console.error('Error fetching total online users:', err);
                return res.status(500).send('Error fetching total online users');
            }
            const totalOnline = totalOnlineResult[0].totalOnline;
                
            connection.query(totalFileQuery, (err, totalFileResult) => {
                if (err) {
                    console.error('Error fetching total File:', err);
                    return res.status(500).send('Error fetching File');
                }
                const totalFile = totalFileResult[0].totalFile;
                
                // Jalankan query grafik
                connection.query(grafikQuery, (err, grafikResults) => {
                    if (err) {
                        console.error('Error fetching grafik data:', err);
                        return res.status(500).send('Error fetching grafik data');
                    }
                    console.log(grafikResults);
                    const grafikLabels = grafikResults.map(row => {
                        const date = new Date(row.upload_date);
                        return date.toLocaleDateString('id-ID');  // Format tanggal sesuai Indonesia
                    });
                    const grafikData = grafikResults.map(row => row.file_count);
                    
                    // Pastikan kamu mengirimkan ID pengguna yang sedang login dari sesi
                    const userId = req.session.userId;  // Atau sesuai dengan nama yang digunakan saat login
                    connection.query(usersQuery, [userId], (err, userResults) => {
                        if (err) {
                            console.error('Error fetching users:', err);
                            return res.status(500).send('Error fetching users');
                        }
                        
                        const username = userResults[0]?.username || 'Unknown';  // Mengambil nama pengguna dari hasil query
                        res.render('admin/dashboard', { 
                            totalUsers, 
                            totalFile,
                            totalOnline,
                            username,
                            grafikLabels,  // Kirimkan label tanggal ke template
                            grafikData     // Kirimkan data jumlah file ke template
                        });
                    });
                });
            });
        });
    });
});
function checkRole(roles) {
    return (req, res, next) => {
        const userRole = req.session.userRole; // Asumsi role disimpan di sesi, bisa disesuaikan sesuai kebutuhan
        if (!userRole || !roles.includes(userRole)) {
            // Mengarahkan ke halaman yang sama dengan menambahkan parameter query 'access_denied'
            return res.redirect('/admin?access_denied=true');
        }
        next();
    };
}

    
    
    // Halaman manajemen Admin - dapat diakses hanya oleh Super Admin
    app.get('/admin_manage', checkAuthenticated, checkRole(['Super Admin']), (req, res) => {
        const usersQuery = 'SELECT id, username, is_online, created_at, roles, role_id FROM users';
        const rolesQuery = 'SELECT * FROM roles';
    
        connection.query(usersQuery, (err, userResults) => {
            if (err) {
                console.error('Error fetching users:', err);
                return res.status(500).send('Error fetching users');
            }
    
            connection.query(rolesQuery, (err, roleResults) => {
                if (err) {
                    console.error('Error fetching roles:', err);
                    return res.status(500).send('Error fetching roles');
                }
    
                // Mengurutkan userResults berdasarkan role
                const roleOrder = ['Super Admin', 'Admin', 'User'];
                userResults.sort((a, b) => {
                    return roleOrder.indexOf(a.roles) - roleOrder.indexOf(b.roles);
                });
    
                res.render('admin/manage', { users: userResults, roles: roleResults }); // Kirim pengguna dan peran ke tampilan
            });
        });
    });
    

    // Rute untuk GET /upload
    app.get('/upload', checkAuthenticated,checkRole('Admin', 'Super Admin') ,(req, res) => {
        res.render('upload');
    });

    // Super Admin menambahkan pengguna atau admin baru
    // Pembaruan middleware unggah untuk menambahkan pengguna
    const uploadUserPhoto = multer({ storage: storage }).single('photo'); // Gunakan multer untuk unggahan foto pengguna

    app.post('/admin/add-user', checkAuthenticated, uploadUserPhoto, async (req, res) => {
        const { username, password, role } = req.body; // 'role' adalah nama peran (contoh: 'Admin')
        const photoPath = req.file ? req.file.path : null;
    
        try {
            const hash = await bcrypt.hash(password, 10);
    
            // Periksa apakah role sudah ada
            const checkRoleQuery = 'SELECT id FROM roles WHERE role_name = ?';
            connection.query(checkRoleQuery, [role], (err, roleResults) => {
                if (err) {
                    console.error('Error checking role:', err);
                    return res.status(500).send('Error checking role');
                }
    
                if (roleResults.length === 0) {
                    // Tambahkan role jika belum ada
                    const insertRoleQuery = 'INSERT INTO roles (role_name) VALUES (?)';
                    connection.query(insertRoleQuery, [role], (err, insertResults) => {
                        if (err) {
                            console.error('Error adding role:', err);
                            return res.status(500).send('Error adding role');
                        }
    
                        const roleId = insertResults.insertId;
                        addUser(username, hash, roleId, role, photoPath, res);
                    });
                } else {
                    const roleId = roleResults[0].id;
                    addUser(username, hash, roleId, role, photoPath, res);
                }
            });
        } catch (err) {
            console.error('Error hashing password:', err);
            return res.status(500).send('Error hashing password');
        }
    });
    
    function addUser(username, hash, roleId, roleName, photoPath, res) {
      const query = 'INSERT INTO users (id, username, password, role_id, roles, photo) VALUES (?, ?, ?, ?, ?, ?)';
const userId = null; // MySQL akan mengatur nilai ID secara otomatis jika null diberikan
connection.query(query, [userId, username, hash, roleId, roleName, photoPath], (err) => {
    if (err) {
        console.error('Error inserting user:', err);
        return res.status(500).send('Error inserting user');
    }

    console.log('User added successfully');
    res.redirect('/admin_manage');
});

    }
    
    
    app.post('/admin/delete-admin', checkAuthenticated, checkRole('Super Admin'), (req, res) => {
        const { userId } = req.body;

        const query = 'DELETE FROM users WHERE id = ?';
        connection.query(query, [userId], (err) => {
            if (err) {
                console.error('Error deleting admin:', err);
                return res.status(500).send('Error deleting admin');
            }

            res.redirect('/admin_manage');
        });
    });

    app.get('/admin/edit-admin/:id', checkAuthenticated, checkRole('Super Admin'), (req, res) => {
        const userId = req.params.id;

        const query = 'SELECT * FROM users WHERE id = ?';
        connection.query(query, [userId], (err, results) => {
            if (err) {
                console.error('Error fetching user for edit:', err);
                return res.status(500).send('Error fetching user for edit');
            }

            if (results.length === 0) {
                return res.status(404).send('User not found');
            }

            const user = results[0];
            res.render('admin/edit_admin', { user });
        });
    });
    app.post('/admin/edit-admin/:id', checkAuthenticated, checkRole('Super Admin'), uploadUserPhoto, async (req, res) => {
        const userId = req.params.id;
        const { username, role } = req.body;
        const photoPath = req.file ? req.file.path : null;
    
        try {
            let updatePasswordQuery = '';
            let updatePasswordValue = null;
            
            if (req.body.password) {
                const hash = await bcrypt.hash(req.body.password, 10);
                updatePasswordQuery = `, password = ?`;
                updatePasswordValue = hash;
            }
    
            // Dapatkan role_id berdasarkan nama peran yang dipilih
            const getRoleIdQuery = 'SELECT id FROM roles WHERE role_name = ?';
            connection.query(getRoleIdQuery, [role], (err, roleResults) => {
                if (err) {
                    console.error('Error fetching role:', err);
                    return res.status(500).send('Error fetching role');
                }
    
                if (roleResults.length === 0) {
                    console.error('Role not found');
                    return res.status(404).send('Role not found');
                }
    
                const roleId = roleResults[0].id;
                
                let query = `
                    UPDATE users 
                    SET username = ?, role_id = ?, roles = ?${updatePasswordQuery} 
                    WHERE id = ?
                `;
                let values = [username, roleId, role, userId];
    
                if (req.body.password) {
                    values.splice(3, 0, updatePasswordValue);
                }
    
                // Jika ada foto yang diunggah, perbarui juga kolom foto
                if (photoPath) {
                    query = `
                        UPDATE users 
                        SET username = ?, role_id = ?, roles = ?, photo = ?${updatePasswordQuery} 
                        WHERE id = ?
                    `;
                    values = [username, roleId, role, photoPath, userId];
    
                    if (req.body.password) {
                        values.splice(4, 0, updatePasswordValue);
                    }
                }
    
                connection.query(query, values, (err) => {
                    if (err) {
                        console.error('Error updating user:', err);
                        return res.status(500).send('Error updating user');
                    }
                    res.redirect('/admin_manage'); 
                });
            });
        } catch (err) {
            console.error('Error hashing password:', err);
            return res.status(500).send('Error hashing password');
        }
    });
    
    app.get('/profile', checkAuthenticated, (req, res) => {
        const userId = req.session.userId; 

        const query = `
            SELECT u.username, u.created_at, u.is_online, u.role_id, r.role_name, u.photo AS profile_photo
            FROM users u 
            JOIN roles r ON u.role_id = r.id 
            WHERE u.id = ?
        `;

        connection.query(query, [userId], (err, results) => {
            if (err) {
                console.error('Error fetching user profile:', err);
                return res.status(500).send('Error fetching user profile');
            }

            if (results.length === 0) {
                return res.status(404).send('User not found');
            }

            const userProfile = results[0]; // Get the first (and only) user result
            res.render('profile', { user: userProfile }); // Render the profile view with user data
        });
    });

    app.get('/admin/download-file/:fileId', checkAuthenticated, checkRole('Admin', 'Super Admin'), (req, res) => {
        const { fileId } = req.params;
    
        // Query database untuk mendapatkan detail file
        const query = 'SELECT * FROM bank_files WHERE id = ?';
        connection.query(query, [fileId], (err, results) => {
            if (err || results.length === 0) {
                console.error('Error fetching file:', err);
                return res.status(500).send('File not found');
            }
    
            const file = results[0];
    
            // Format tanggal menggunakan moment
            const formattedDate = moment(file.date).format('MMM D, YYYY');
            const formattedCreatedAt = moment(file.created_at).format('MMM D, YYYY');
    
            // Membuat dokumen PDF
            const doc = new PDFDocument();
            const fileName = `file_${file.borrower_name.replace(/[^a-zA-Z0-9-_]/g, '')}.pdf`;
    
            // Set header respons untuk file PDF
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    
            // Pipe dokumen ke respons
            doc.pipe(res);
    
            // Menambahkan Kop Surat
            doc.image(path.join(__dirname, 'views', 'admin', 'logo_bank.png'), 40, 10, { width: 100 }) // Ganti dengan path logo bank
                .fontSize(18)
                .font('Helvetica-Bold')
                .fillColor('#1E3A8A')
                .text('Bank BRI', 160, 30); // Nama Bank
            doc.fontSize(10).font('Helvetica').fillColor('#000000')
                .text('Jl. Raya Teuku Umar No.Km.43, Wanasari, Kec. Cibitung, Kabupaten Bekasi.', 160, 50) // Alamat Bank
                .text('Phone: (021) 12345678 | Email: bri@gamil.co.id', 160, 65); // Kontak Bank
            // Garis pemisah setelah kop surat
            doc.moveDown(2);
            doc.strokeColor('#1E3A8A').lineWidth(1).moveTo(50, 80).lineTo(550, 80).stroke();
            // Header PDF
            doc.fontSize(24).font('Helvetica-Bold').fillColor('#1E3A8A').text('File Details', { align: 'center' });
            doc.moveDown(2);
            // Data tabel
            const tableData = [
                ['Field', 'Value'],
                ['File Number', `${file.room_number} - ${file.safe_number} - ${file.shelf_number} - ${file.file_sequence}`],
                ['Date', formattedDate],
                ['Loan Amount', file.loan_amount],
                ['Borrower\'s Name', file.borrower_name],
                ['Marketing', file.marketing],
                ['Created At', formattedCreatedAt],
            ];
            const tableStartX = 50;
            let tableStartY = doc.y;
            const columnWidths = [150, 300];
            const rowHeight = 25;
    
            doc.fontSize(12).font('Helvetica-Bold').fillColor('#FFFFFF').rect(tableStartX, tableStartY, columnWidths[0], rowHeight).fill('#1E3A8A');
            doc.text(tableData[0][0], tableStartX + 5, tableStartY + 5, { width: columnWidths[0], align: 'left' });
            doc.rect(tableStartX + columnWidths[0], tableStartY, columnWidths[1], rowHeight).fill('#1E3A8A');
            doc.text(tableData[0][1], tableStartX + columnWidths[0] + 5, tableStartY + 5, { width: columnWidths[1], align: 'left' });
    
            doc.strokeColor('#1E3A8A').lineWidth(1).moveTo(tableStartX, tableStartY + rowHeight).lineTo(tableStartX + columnWidths[0] + columnWidths[1], tableStartY + rowHeight).stroke();
    
            tableData.slice(1).forEach((row, rowIndex) => {
                tableStartY += rowHeight;
                const isEvenRow = rowIndex % 2 === 0;
                const rowColor = isEvenRow ? '#F3F4F6' : '#FFFFFF';
    
                doc.rect(tableStartX, tableStartY, columnWidths[0] + columnWidths[1], rowHeight).fill(rowColor);
    
                doc.font('Helvetica').fillColor('#1F2937')
                    .text(row[0], tableStartX + 5, tableStartY + 5, { width: columnWidths[0], align: 'left' })
                    .text(row[1], tableStartX + columnWidths[0] + 5, tableStartY + 5, { width: columnWidths[1], align: 'left' });
    
                doc.strokeColor('#D1D5DB').lineWidth(0.5).moveTo(tableStartX, tableStartY + rowHeight).lineTo(tableStartX + columnWidths[0] + columnWidths[1], tableStartY + rowHeight).stroke();
            });
    
            // Tambahkan tanda tangan di bagian bawah kanan
            doc.moveDown(4); // Tambahkan jarak sebelum tanda tangan
            const signatureY = doc.y + 50; // Posisi Y untuk tanda tangan
            doc.fontSize(12).font('Helvetica').fillColor('#000000')
                .text('Kepala Unit', 400, signatureY - 10, { align: 'center' }) // Judul tanda tangan
                .text('(___________________)', 400, signatureY + 20, { align: 'center' }) // Garis tanda tangan
    
            // Footer
            doc.moveDown(2);
            doc.fontSize(10).font('Helvetica-Oblique').fillColor('#9CA3AF').text('Generated by Bank File Management System', { align: 'center' });
    
            // Selesai menulis ke PDF
            doc.end();
        });
    });
    // Endpoint untuk mengecek nasabah berdasarkan nomor rekening
    app.get('/check-borrow', (req, res) => {
        const { rek } = req.query;
    
        const query = 'SELECT * FROM borrow WHERE rek = ?';
        connection.query(query, [rek], (err, results) => {
            if (err) {
                console.error('Error fetching borrower:', err);
                return res.status(500).json({ success: false, message: 'Error fetching borrower' });
            }
    
            if (results.length > 0) {
                return res.json({ success: true, name: results[0].name });  // Mengirimkan 'name' sebagai borrower_name
            } else {
                return res.json({ success: false, message: 'Borrower not found' });
            }
        });
    });

    
    // Endpoint untuk menampilkan form tambah nasabah
app.get('/add-borrower', (req, res) => {
    res.render('add_borrower');
});
app.get('/admin-borrow', (req, res) => {
    res.render('admin/admin-borrow');
});
app.get('/borrow', (req, res) => {
    const query = 'SELECT * FROM borrow';

    connection.query(query, (err, results) => {
        if (err) {  
            console.error('Error retrieving borrowers:', err);
            return res.status(500).send('Error retrieving borrowers');
        }

        res.render('admin/borrow', { borrow: results });
    });
});
// Endpoint untuk menyimpan nasabah baru
app.post('/add-borrower', (req, res) => {
    const { rek, borrower_name } = req.body;

    const query = 'INSERT INTO borrow (rek, name) VALUES (?, ?)';
    connection.query(query, [rek, borrower_name], (err) => {
        if (err) {
            console.error('Error adding borrower:', err);
            return res.status(500).send('Error adding borrower');
        }

        res.redirect('/home'); // Redirect ke halaman daftar file
    });
});
app.post('/admin-borrow', (req, res) => {
    const { rek, borrower_name } = req.body;

    const query = 'INSERT INTO borrow (rek, name) VALUES (?, ?)';
    connection.query(query, [rek, borrower_name], (err) => {
        if (err) {
            console.error('Error adding borrower:', err);
            return res.status(500).send('Error adding borrower');
        }

        res.redirect('/dashboard'); // Redirect ke halaman daftar file
    });
});
// Render halaman edit borrower
app.get('/edit-borrower/:id', (req, res) => {
    const { id } = req.params;

    const query = 'SELECT * FROM borrow WHERE id = ?';
    connection.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error fetching borrower:', err);
            return res.status(500).send('Error fetching borrower');
        }

        if (results.length === 0) {
            return res.status(404).send('Borrower not found');
        }

        res.render('admin/edit-borrower', { borrower: results[0] });
    });
});

// Handle update borrower
app.post('/edit-borrower/:id', (req, res) => {
    const { id } = req.params;
    const { rek, borrower_name } = req.body;

    const query = 'UPDATE borrow SET rek = ?, name = ? WHERE id = ?';
    connection.query(query, [rek, borrower_name, id], (err) => {
        if (err) {
            console.error('Error updating borrower:', err);
            return res.status(500).send('Error updating borrower');
        }

        res.redirect('/borrow'); // Redirect ke halaman daftar file
    });
});
app.post('/delete-borrower/:id', (req, res) => {
    const { id } = req.params;

    // Query untuk menghapus borrower berdasarkan ID
    const query = 'DELETE FROM borrow WHERE id = ?';
    
    connection.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error deleting borrower:', err);
            return res.status(500).send('Error deleting borrower');
        }

        if (results.affectedRows === 0) {
            return res.status(404).send('Borrower not found');
        }

        // Redirect ke halaman daftar borrower setelah penghapusan
        res.redirect('/borrow'); // Sesuaikan dengan URL yang menampilkan daftar borrower
    });
});

    // Mulai server
    app.listen(3000, () => {
        console.log('Server running on http://localhost:3000');
    });
