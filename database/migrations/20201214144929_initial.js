exports.up = function (knex) {
  return knex.schema
    .createTable("users", (table) => {
      table.increments();
      table.string("username", 128).notNullable().unique().index();
      table.string("password", 256).notNullable();
    });
};

exports.down = function (knex) {
  return knex.schema.dropTableIfExists("users");
};
