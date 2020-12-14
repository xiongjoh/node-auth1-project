const db = require('../database/connection')

module.exports = {
    find() {
        return db('users').orderBy('id')
    },
    findBy(filter) {
        return db('users').where(filter).orderBy('id')
    },
    async add(user) {
        const [id] = await db('users').insert(user, 'id')
        return this.findById(id)
    },
    findById(id) {
        return db('users').where({ id }).first()
    }
}