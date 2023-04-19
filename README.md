# ceremonyclient

KZG Ceremony client for Quilibrium. 

# Running

Use node 16+ `nvm use 16.15.1`

Run with `go run ./... <voucher_filename>` or omit the filename to write to quil_voucher.hex.

If you have docker installed you can participate in the ceremony by simply running `make participate`. Your voucher will be written to `vouchers/`.
