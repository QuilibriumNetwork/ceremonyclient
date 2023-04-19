# ceremonyclient

KZG Ceremony client for Quilibrium. 

# Running

Run with `go run ./... <voucher_filename>` or omit the filename to write to quil_voucher.hex.

If you have docker installed you can participate in the ceremony by simply running `make participate`. Your voucher will be written to `vouchers/`.

## Additional Features

Run with `go run ./... verify-transcript` to verify the latest state of the sequencer, or `go run ./... check-voucher <voucher_filename>` to verify voucher inclusion in the latest state. Please keep in mind voucher inclusions are not immediate after contribution – the current batch must be processed before it will appear, and if there was an error response from the sequencer when contributing the voucher will not be included. 
