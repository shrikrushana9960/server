
const validator = (keys, req) => {
    let body;
    let missing = [];
    if (req.method === 'GET') {
        body = req.query;
    } else {
        body = req.body;
    }

    keys.forEach(item => {
        if (!body[item]) {
            missing.push(item)
        }
    });
   return missing;
};


module.exports = validator;
