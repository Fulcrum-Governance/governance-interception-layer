// Benign: simple base64 encoding — no execution
const data = btoa('hello');
const decoded = atob(data);
console.log(decoded);
