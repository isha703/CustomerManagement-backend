-- Add created_by column to customers so entity mapping can persist audit info
ALTER TABLE customers
  ADD COLUMN IF NOT EXISTS created_by VARCHAR(255);

-- Optional: backfill created_by from an existing email field if appropriate
-- UPDATE customers SET created_by = email WHERE created_by IS NULL;
