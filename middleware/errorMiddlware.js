const errorHandler = (err, req, res, next) => {
    const statusCode = err.status || 500;
    const message = err.message || "Something went wrong.";
    const stack = process.env.NODE_ENV === 'production' ? undefined : err.stack;

    return res.status(statusCode).json({
        success: false,
        code: statusCode,
        message: message,
        stack: stack
    });
   
};

module.exports = errorHandler;
