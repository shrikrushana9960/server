const mongoose = require('mongoose');

const DB = process.env.DATABASE;

exports.dbConnect = () => {
    mongoose.connect(DB).then(() => {
        console.log('DB Connected Successfully')
    }).catch((e) => {
        console.log(e)
    })
}