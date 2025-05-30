-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens(token,created_at,updated_at,user_id,expires_at)
VALUES(
    $1,
    NOW(),
    NOW(),
    $2,
    $3
)
RETURNING *;

-- name: GetRefreshByToken :one
SELECT * FROM refresh_tokens WHERE token = $1;

-- name: GetUserByRefreshToken :one
SELECT users.* FROM refresh_tokens INNER JOIN users
ON users.id = refresh_tokens.user_id
WHERE refresh_tokens.token = $1;

-- name: RevokeToken :exec
UPDATE refresh_tokens SET revoked_at = $2,updated_at = NOW() WHERE token = $1;
