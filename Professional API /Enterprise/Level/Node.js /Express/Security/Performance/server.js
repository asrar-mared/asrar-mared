// 🚀 Professional API - Enterprise Level
// Node.js + Express + Security + Performance + Monitoring

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const morgan = require('morgan');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const redis = require('redis');
const { body, validationResult, param, query } = require('express-validator');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const prometheus = require('prom-client');
const fs = require('fs').promises;
const path = require('path');

// 🔧 Configuration Management
class Config {
    constructor() {
        this.env = process.env.NODE_ENV || 'development';
        this.port = process.env.PORT || 3000;
        this.jwtSecret = process.env.JWT_SECRET || 'your-super-secret-key';
        this.mongoUrl = process.env.MONGO_URL || 'mongodb://localhost:27017/professional-api';
        this.redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
        this.apiVersion = 'v1';
        this.maxRequestSize = '10mb';
        this.corsOrigins = process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'];
    }
}

// 📊 Logging System
class Logger {
    constructor() {
        this.logger = winston.createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.colorize(),
                winston.format.printf(({ timestamp, level, message, stack }) => {
                    return `${timestamp} [${level}]: ${stack || message}`;
                })
            ),
            transports: [
                new winston.transports.Console(),
                new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
                new winston.transports.File({ filename: 'logs/combined.log' }),
            ],
        });
    }

    info(message, meta = {}) { this.logger.info(message, meta); }
    error(message, meta = {}) { this.logger.error(message, meta); }
    warn(message, meta = {}) { this.logger.warn(message, meta); }
    debug(message, meta = {}) { this.logger.debug(message, meta); }
}

// 📈 Metrics and Monitoring
class MetricsCollector {
    constructor() {
        this.register = prometheus.register;
        
        // Default metrics
        prometheus.collectDefaultMetrics({ register: this.register });
        
        // Custom metrics
        this.httpRequestDuration = new prometheus.Histogram({
            name: 'http_request_duration_seconds',
            help: 'Duration of HTTP requests in seconds',
            labelNames: ['method', 'route', 'status_code'],
            buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
        });

        this.httpRequestTotal = new prometheus.Counter({
            name: 'http_requests_total',
            help: 'Total number of HTTP requests',
            labelNames: ['method', 'route', 'status_code']
        });

        this.activeConnections = new prometheus.Gauge({
            name: 'active_connections',
            help: 'Number of active connections'
        });

        this.dbConnectionPool = new prometheus.Gauge({
            name: 'db_connection_pool_size',
            help: 'Database connection pool size'
        });
    }

    middleware() {
        return (req, res, next) => {
            const start = Date.now();
            
            res.on('finish', () => {
                const duration = (Date.now() - start) / 1000;
                const route = req.route ? req.route.path : req.url;
                
                this.httpRequestDuration
                    .labels(req.method, route, res.statusCode)
                    .observe(duration);
                
                this.httpRequestTotal
                    .labels(req.method, route, res.statusCode)
                    .inc();
            });
            
            next();
        };
    }
}

// 🔐 Authentication & Authorization
class AuthService {
    constructor(jwtSecret, logger) {
        this.jwtSecret = jwtSecret;
        this.logger = logger;
        this.saltRounds = 12;
    }

    async hashPassword(password) {
        return await bcrypt.hash(password, this.saltRounds);
    }

    async verifyPassword(password, hashedPassword) {
        return await bcrypt.compare(password, hashedPassword);
    }

    generateToken(payload, expiresIn = '24h') {
        return jwt.sign(payload, this.jwtSecret, { expiresIn });
    }

    verifyToken(token) {
        try {
            return jwt.verify(token, this.jwtSecret);
        } catch (error) {
            this.logger.error('JWT verification failed', { error: error.message });
            return null;
        }
    }

    // Middleware للمصادقة
    authenticate() {
        return (req, res, next) => {
            const authHeader = req.headers.authorization;
            const token = authHeader && authHeader.split(' ')[1];

            if (!token) {
                return res.status(401).json({
                    success: false,
                    error: 'Access token required',
                    code: 'TOKEN_MISSING'
                });
            }

            const decoded = this.verifyToken(token);
            if (!decoded) {
                return res.status(401).json({
                    success: false,
                    error: 'Invalid or expired token',
                    code: 'TOKEN_INVALID'
                });
            }

            req.user = decoded;
            next();
        };
    }

    // Middleware للتحكم في الصلاحيات
    authorize(roles = []) {
        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    error: 'Authentication required',
                    code: 'AUTH_REQUIRED'
                });
            }

            if (roles.length && !roles.includes(req.user.role)) {
                return res.status(403).json({
                    success: false,
                    error: 'Insufficient permissions',
                    code: 'PERMISSION_DENIED'
                });
            }

            next();
        };
    }
}

// 💾 Database Models
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true, minlength: 8 },
    role: { type: String, enum: ['user', 'admin', 'moderator'], default: 'user' },
    profile: {
        firstName: String,
        lastName: String,
        avatar: String,
        bio: String
    },
    settings: {
        theme: { type: String, enum: ['light', 'dark'], default: 'light' },
        notifications: { type: Boolean, default: true },
        language: { type: String, default: 'en' }
    },
    isActive: { type: Boolean, default: true },
    lastLogin: Date,
    loginAttempts: { type: Number, default: 0 },
    lockoutUntil: Date
}, {
    timestamps: true,
    toJSON: { virtuals: true, transform: (doc, ret) => {
        delete ret.password;
        delete ret.__v;
        return ret;
    }}
});

const PostSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true, maxlength: 200 },
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    tags: [{ type: String, trim: true }],
    category: { type: String, required: true },
    status: { type: String, enum: ['draft', 'published', 'archived'], default: 'draft' },
    metadata: {
        views: { type: Number, default: 0 },
        likes: { type: Number, default: 0 },
        shares: { type: Number, default: 0 }
    },
    publishedAt: Date
}, {
    timestamps: true
});

// 🚀 Main API Class
class ProfessionalAPI {
    constructor() {
        this.config = new Config();
        this.logger = new Logger();
        this.metrics = new MetricsCollector();
        this.auth = new AuthService(this.config.jwtSecret, this.logger);
        this.app = express();
        this.server = null;
        this.redis = null;
        
        this.initializeModels();
        this.setupMiddleware();
        this.setupRoutes();
        this.setupSwagger();
        this.setupErrorHandling();
    }

    initializeModels() {
        this.User = mongoose.model('User', UserSchema);
        this.Post = mongoose.model('Post', PostSchema);
    }

    // إعداد الMiddleware
    setupMiddleware() {
        // Security headers
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    imgSrc: ["'self'", "data:", "https:"]
                }
            }
        }));

        // CORS
        this.app.use(cors({
            origin: this.config.corsOrigins,
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
        }));

        // Compression
        this.app.use(compression());

        // Request parsing
        this.app.use(express.json({ limit: this.config.maxRequestSize }));
        this.app.use(express.urlencoded({ extended: true, limit: this.config.maxRequestSize }));

        // Logging
        this.app.use(morgan('combined', {
            stream: { write: (message) => this.logger.info(message.trim()) }
        }));

        // Metrics
        this.app.use(this.metrics.middleware());

        // Rate limiting
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 100, // requests per window
            message: {
                success: false,
                error: 'Too many requests, please try again later',
                code: 'RATE_LIMIT_EXCEEDED'
            },
            standardHeaders: true,
            legacyHeaders: false,
        });

        const speedLimiter = slowDown({
            windowMs: 15 * 60 * 1000,
            delayAfter: 50,
            delayMs: 500,
            maxDelayMs: 20000
        });

        this.app.use('/api/', limiter);
        this.app.use('/api/', speedLimiter);
    }

    // إعداد المسارات
    setupRoutes() {
        const router = express.Router();

        // Health Check
        router.get('/health', (req, res) => {
            res.json({
                success: true,
                data: {
                    status: 'healthy',
                    timestamp: new Date().toISOString(),
                    version: require('./package.json')?.version || '1.0.0',
                    environment: this.config.env,
                    uptime: process.uptime()
                }
            });
        });

        // Metrics endpoint
        router.get('/metrics', async (req, res) => {
            res.set('Content-Type', this.metrics.register.contentType);
            res.end(await this.metrics.register.metrics());
        });

        // Authentication routes
        this.setupAuthRoutes(router);
        
        // User routes
        this.setupUserRoutes(router);
        
        // Post routes
        this.setupPostRoutes(router);

        // Mount router
        this.app.use(`/api/${this.config.apiVersion}`, router);
    }

    setupAuthRoutes(router) {
        // Register
        router.post('/auth/register', [
            body('username').isLength({ min: 3, max: 30 }).trim(),
            body('email').isEmail().normalizeEmail(),
            body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        ], async (req, res, next) => {
            try {
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({
                        success: false,
                        error: 'Validation failed',
                        details: errors.array()
                    });
                }

                const { username, email, password, profile } = req.body;

                // Check if user exists
                const existingUser = await this.User.findOne({ 
                    $or: [{ email }, { username }] 
                });

                if (existingUser) {
                    return res.status(409).json({
                        success: false,
                        error: 'User already exists',
                        code: 'USER_EXISTS'
                    });
                }

                // Create user
                const hashedPassword = await this.auth.hashPassword(password);
                const user = new this.User({
                    username,
                    email,
                    password: hashedPassword,
                    profile: profile || {}
                });

                await user.save();

                // Generate token
                const token = this.auth.generateToken({
                    userId: user._id,
                    username: user.username,
                    role: user.role
                });

                this.logger.info('User registered successfully', { userId: user._id });

                res.status(201).json({
                    success: true,
                    data: {
                        user: user.toJSON(),
                        token
                    },
                    message: 'Registration successful'
                });

            } catch (error) {
                next(error);
            }
        });

        // Login
        router.post('/auth/login', [
            body('login').notEmpty().trim(), // username or email
            body('password').notEmpty()
        ], async (req, res, next) => {
            try {
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({
                        success: false,
                        error: 'Validation failed',
                        details: errors.array()
                    });
                }

                const { login, password } = req.body;

                // Find user by email or username
                const user = await this.User.findOne({
                    $or: [{ email: login }, { username: login }]
                });

                if (!user || !(await this.auth.verifyPassword(password, user.password))) {
                    return res.status(401).json({
                        success: false,
                        error: 'Invalid credentials',
                        code: 'INVALID_CREDENTIALS'
                    });
                }

                if (!user.isActive) {
                    return res.status(403).json({
                        success: false,
                        error: 'Account is deactivated',
                        code: 'ACCOUNT_DEACTIVATED'
                    });
                }

                // Update last login
                user.lastLogin = new Date();
                user.loginAttempts = 0;
                await user.save();

                // Generate token
                const token = this.auth.generateToken({
                    userId: user._id,
                    username: user.username,
                    role: user.role
                });

                this.logger.info('User logged in successfully', { userId: user._id });

                res.json({
                    success: true,
                    data: {
                        user: user.toJSON(),
                        token
                    },
                    message: 'Login successful'
                });

            } catch (error) {
                next(error);
            }
        });
    }

    setupUserRoutes(router) {
        // Get current user profile
        router.get('/users/me', this.auth.authenticate(), async (req, res, next) => {
            try {
                const user = await this.User.findById(req.user.userId);
                if (!user) {
                    return res.status(404).json({
                        success: false,
                        error: 'User not found',
                        code: 'USER_NOT_FOUND'
                    });
                }

                res.json({
                    success: true,
                    data: user.toJSON()
                });
            } catch (error) {
                next(error);
            }
        });

        // Update user profile
        router.put('/users/me', [
            this.auth.authenticate(),
            body('profile.firstName').optional().trim().isLength({ min: 1, max: 50 }),
            body('profile.lastName').optional().trim().isLength({ min: 1, max: 50 }),
            body('profile.bio').optional().trim().isLength({ max: 500 })
        ], async (req, res, next) => {
            try {
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({
                        success: false,
                        error: 'Validation failed',
                        details: errors.array()
                    });
                }

                const updates = {};
                if (req.body.profile) updates.profile = req.body.profile;
                if (req.body.settings) updates.settings = req.body.settings;

                const user = await this.User.findByIdAndUpdate(
                    req.user.userId,
                    { $set: updates },
                    { new: true, runValidators: true }
                );

                res.json({
                    success: true,
                    data: user.toJSON(),
                    message: 'Profile updated successfully'
                });
            } catch (error) {
                next(error);
            }
        });

        // Get all users (admin only)
        router.get('/users', [
            this.auth.authenticate(),
            this.auth.authorize(['admin']),
            query('page').optional().isInt({ min: 1 }).toInt(),
            query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
            query('search').optional().trim()
        ], async (req, res, next) => {
            try {
                const page = req.query.page || 1;
                const limit = req.query.limit || 20;
                const skip = (page - 1) * limit;
                const search = req.query.search;

                let query = {};
                if (search) {
                    query = {
                        $or: [
                            { username: { $regex: search, $options: 'i' } },
                            { email: { $regex: search, $options: 'i' } },
                            { 'profile.firstName': { $regex: search, $options: 'i' } },
                            { 'profile.lastName': { $regex: search, $options: 'i' } }
                        ]
                    };
                }

                const [users, total] = await Promise.all([
                    this.User.find(query).skip(skip).limit(limit).sort({ createdAt: -1 }),
                    this.User.countDocuments(query)
                ]);

                res.json({
                    success: true,
                    data: {
                        users,
                        pagination: {
                            page,
                            limit,
                            total,
                            pages: Math.ceil(total / limit)
                        }
                    }
                });
            } catch (error) {
                next(error);
            }
        });
    }

    setupPostRoutes(router) {
        // Create post
        router.post('/posts', [
            this.auth.authenticate(),
            body('title').trim().isLength({ min: 1, max: 200 }),
            body('content').trim().isLength({ min: 1 }),
            body('category').trim().notEmpty(),
            body('tags').optional().isArray()
        ], async (req, res, next) => {
            try {
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({
                        success: false,
                        error: 'Validation failed',
                        details: errors.array()
                    });
                }

                const post = new this.Post({
                    ...req.body,
                    author: req.user.userId
                });

                await post.save();
                await post.populate('author', 'username profile.firstName profile.lastName');

                this.logger.info('Post created', { postId: post._id, authorId: req.user.userId });

                res.status(201).json({
                    success: true,
                    data: post,
                    message: 'Post created successfully'
                });
            } catch (error) {
                next(error);
            }
        });

        // Get posts
        router.get('/posts', [
            query('page').optional().isInt({ min: 1 }).toInt(),
            query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
            query('category').optional().trim(),
            query('status').optional().isIn(['draft', 'published', 'archived']),
            query('author').optional().isMongoId()
        ], async (req, res, next) => {
            try {
                const page = req.query.page || 1;
                const limit = req.query.limit || 20;
                const skip = (page - 1) * limit;

                let query = {};
                if (req.query.category) query.category = req.query.category;
                if (req.query.status) query.status = req.query.status;
                if (req.query.author) query.author = req.query.author;

                // Non-authenticated users can only see published posts
                if (!req.user) query.status = 'published';

                const [posts, total] = await Promise.all([
                    this.Post.find(query)
                        .populate('author', 'username profile.firstName profile.lastName profile.avatar')
                        .skip(skip)
                        .limit(limit)
                        .sort({ createdAt: -1 }),
                    this.Post.countDocuments(query)
                ]);

                res.json({
                    success: true,
                    data: {
                        posts,
                        pagination: {
                            page,
                            limit,
                            total,
                            pages: Math.ceil(total / limit)
                        }
                    }
                });
            } catch (error) {
                next(error);
            }
        });

        // Get single post
        router.get('/posts/:id', [
            param('id').isMongoId()
        ], async (req, res, next) => {
            try {
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({
                        success: false,
                        error: 'Invalid post ID'
                    });
                }

                const post = await this.Post.findById(req.params.id)
                    .populate('author', 'username profile.firstName profile.lastName profile.avatar');

                if (!post) {
                    return res.status(404).json({
                        success: false,
                        error: 'Post not found',
                        code: 'POST_NOT_FOUND'
                    });
                }

                // Increment view count
                await this.Post.findByIdAndUpdate(post._id, { $inc: { 'metadata.views': 1 } });

                res.json({
                    success: true,
                    data: post
                });
            } catch (error) {
                next(error);
            }
        });
    }

    // إعداد Swagger Documentation
    setupSwagger() {
        const options = {
            definition: {
                openapi: '3.0.0',
                info: {
                    title: 'Professional API',
                    version: '1.0.0',
                    description: 'Enterprise-level RESTful API with authentication, validation, and monitoring',
                    contact: {
                        name: 'API Support',
                        email: 'support@yourcompany.com'
                    }
                },
                servers: [
                    {
                        url: `http://localhost:${this.config.port}/api/${this.config.apiVersion}`,
                        description: 'Development server'
                    }
                ],
                components: {
                    securitySchemes: {
                        bearerAuth: {
                            type: 'http',
                            scheme: 'bearer',
                            bearerFormat: 'JWT'
                        }
                    },
                    schemas: {
                        User: {
                            type: 'object',
                            properties: {
                                _id: { type: 'string' },
                                username: { type: 'string' },
                                email: { type: 'string' },
                                role: { type: 'string', enum: ['user', 'admin', 'moderator'] },
                                profile: {
                                    type: 'object',
                                    properties: {
                                        firstName: { type: 'string' },
                                        lastName: { type: 'string' },
                                        avatar: { type: 'string' },
                                        bio: { type: 'string' }
                                    }
                                }
                            }
                        },
                        Post: {
                            type: 'object',
                            properties: {
                                _id: { type: 'string' },
                                title: { type: 'string' },
                                content: { type: 'string' },
                                author: { $ref: '#/components/schemas/User' },
                                category: { type: 'string' },
                                tags: { type: 'array', items: { type: 'string' } },
                                status: { type: 'string', enum: ['draft', 'published', 'archived'] }
                            }
                        }
                    }
                }
            },
            apis: ['./routes/*.js', './models/*.js']
        };

        const specs = swaggerJsdoc(options);
        this.app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(specs, {
            customCss: '.swagger-ui .topbar { display: none }',
            customSiteTitle: "Professional API Documentation"
        }));
    }

    // معالجة الأخطاء
    setupErrorHandling() {
        // 404 handler
        this.app.use('*', (req, res) => {
            res.status(404).json({
                success: false,
                error: 'Endpoint not found',
                code: 'NOT_FOUND'
            });
        });

        // Global error handler
        this.app.use((error, req, res, next) => {
            this.logger.error('API Error', {
                error: error.message,
                stack: error.stack,
                url: req.url,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });

            // Mongoose validation error
            if (error.name === 'ValidationError') {
                return res.status(400).json({
                    success: false,
                    error: 'Validation failed',
                    details: Object.values(error.errors).map(e => ({
                        field: e.path,
                        message: e.message
                    }))
                });
            }

            // Mongoose duplicate key error
            if (error.code === 11000) {
                const field = Object.keys(error.keyValue)[0];
                return res.status(409).json({
                    success: false,
                    error: `${field} already exists`,
                    code: 'DUPLICATE_ENTRY'
                });
            }

            // JWT errors
            if (error.name === 'JsonWebTokenError') {
                return res.status(401).json({
                    success: false,
                    error: 'Invalid token',
                    code: 'INVALID_TOKEN'
                });
            }

            // Default error
            const status = error.status || 500;
            res.status(status).json({
                success: false,
                error: this.config.env === 'production' ? 'Internal server error' : error.message,
                code: 'INTERNAL_ERROR',
                ...(this.config.env !== 'production' && { stack: error.stack })
            });
        });
    }

    // اتصال بقاعدة البيانات
    async connectDatabase() {
        try {
            await mongoose.connect(this.config.mongoUrl, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                maxPoolSize: 10,
                serverSelectionTimeoutMS: 5000,
                socketTimeoutMS: 45000
            });
            this.logger.info('Connected to MongoDB successfully');
        } catch (error) {
            this.logger.error('MongoDB connection failed', { error: error.message });
            process.exit(1);
        }
    }

    // اتصال بـ Redis
    async connectRedis() {
        try {
            this.redis = redis.createClient({ url: this.config.redisUrl });
            await this.redis.connect();
            this.logger.info('Connected to Redis successfully');
        } catch (error) {
            this.logger.warn('Redis connection failed', { error: error.message });
        }
    }

    // بدء الخادم
    async start() {
        try {
            // إنشاء مجلد logs إذا لم يكن موجود
            await fs.mkdir('logs', { recursive: true });

            // الاتصال بقواعد البيانات
            await this.connectDatabase();
            await this.connectRedis();

            // بدء الخادم
            this.server = this.app.listen(this.config.port, () => {
                this.logger.info(`🚀 Professional API server started on port ${this.config.port}`);
                this.logger.info(`📚 API Documentation: http://localhost:${this.config.port}/api/docs`);
                this.logger.info(`📊 Metrics: http://localhost:${this.config.port}/api/${this.config.apiVersion}/metrics`);
                this.logger.info(`🏥 Health Check: http://localhost:${this.config.port}/api/${this.config.apiVersion}/health`);
            });

            // Graceful shutdown
            process.on('SIGTERM', () => this.shutdown());
            process.on('SIGINT', () => this.shutdown());

        } catch (error) {
            this.logger.error('Failed to start server', { error: error.message });
            process.exit(1);
        }
    }

    // إيقاف الخادم بأمان
    async shutdown() {
        this.logger.info('🔄 Graceful shutdown initiated...');

        try {
            // إيقاف HTTP server
            if (this.server) {
                await new Promise((resolve) => {
                    this.server.close(resolve);
                });
                this.logger.info('✅ HTTP server closed');
            }

            // إغلاق اتصال MongoDB
            if (mongoose.connection.readyState === 1) {
