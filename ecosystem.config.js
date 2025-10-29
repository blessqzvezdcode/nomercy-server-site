module.exports = {
  apps: [{
    name: 'nomercy-server',
    script: 'server.js',
    instances: 'max', // Use all available CPU cores
    exec_mode: 'cluster',
    
    // Environment variables
    env: {
      NODE_ENV: 'development',
      PORT: 3000
    },
    env_production: {
      NODE_ENV: 'production',
      PORT: 3000,
      HOST: '0.0.0.0'
    },
    
    // Logging
    log_file: './logs/pm2-combined.log',
    out_file: './logs/pm2-out.log',
    error_file: './logs/pm2-error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    
    // Auto restart settings
    watch: false, // Don't watch files in production
    ignore_watch: ['node_modules', 'logs', 'public/uploads'],
    max_restarts: 10,
    min_uptime: '10s',
    
    // Memory management
    max_memory_restart: '1G',
    
    // Advanced settings
    kill_timeout: 5000,
    listen_timeout: 3000,
    
    // Health monitoring
    health_check_grace_period: 3000,
    
    // Source map support
    source_map_support: true,
    
    // Merge logs from all instances
    merge_logs: true,
    
    // Auto restart on file changes (development only)
    watch_delay: 1000,
    
    // Graceful shutdown
    shutdown_with_message: true,
    
    // Node.js options
    node_args: '--max-old-space-size=1024'
  }],

  // Deployment configuration
  deploy: {
    production: {
      user: 'deploy',
      host: 'your-server.com',
      ref: 'origin/main',
      repo: 'git@github.com:username/nomercy-server-site.git',
      path: '/var/www/nomercy-server-site',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && npm run setup && pm2 reload ecosystem.config.js --env production',
      'pre-setup': ''
    }
  }
};
