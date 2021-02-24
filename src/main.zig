const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const rotr = std.math.rotr;

pub const CraxS = struct {
    const N_STEPS: usize = 10;
    const RCON = [5]u32{ 0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB };

    /// A secret key
    pub const Key = struct {
        w: [4]u32,

        pub fn init(bytes: [16]u8) Key {
            return Key{
                .w = [4]u32{
                    mem.readIntLittle(u32, bytes[0..4]),
                    mem.readIntLittle(u32, bytes[4..8]),
                    mem.readIntLittle(u32, bytes[8..12]),
                    mem.readIntLittle(u32, bytes[12..16]),
                },
            };
        }
    };

    /// Apply the Alzette box
    pub fn alzette(x: *u32, y: *u32, comptime c: u32) callconv(.Inline) void {
        x.* +%= rotr(u32, y.*, 31);
        y.* +%= rotr(u32, x.*, 24);
        x.* ^= c;
        x.* +%= rotr(u32, y.*, 17);
        y.* +%= rotr(u32, x.*, 17);
        x.* ^= c;
        x.* +%= y.*;
        y.* +%= rotr(u32, x.*, 31);
        x.* ^= c;
        x.* +%= rotr(u32, y.*, 24);
        y.* +%= rotr(u32, x.*, 16);
        x.* ^= c;
    }

    /// Apply the inverse Alzette box
    pub fn alzetteInv(x: *u32, y: *u32, comptime c: u32) callconv(.Inline) void {
        x.* ^= c;
        y.* -%= rotr(u32, x.*, 16);
        x.* -%= rotr(u32, y.*, 24);
        x.* ^= c;
        y.* -%= rotr(u32, x.*, 31);
        x.* -%= y.*;
        x.* ^= c;
        y.* -%= rotr(u32, x.*, 17);
        x.* -%= rotr(u32, y.*, 17);
        x.* ^= c;
        y.* -%= rotr(u32, x.*, 24);
        x.* -%= rotr(u32, y.*, 31);
    }

    fn _encrypt(x: *u32, y: *u32, k: Key) void {
        comptime var step: u32 = 0;
        inline while (step < N_STEPS) : (step +%= 1) {
            x.* ^= step ^ k.w[2 * (step % 2)];
            y.* ^= step ^ k.w[2 * (step % 2) + 1];
            alzette(x, y, RCON[step % 5]);
        }
        x.* ^= k.w[0];
        y.* ^= k.w[1];
    }

    fn _decrypt(x: *u32, y: *u32, k: Key) void {
        x.* ^= k.w[0];
        y.* ^= k.w[1];
        comptime var step: u32 = N_STEPS - 1;
        inline while (true) : (step -= 1) {
            alzetteInv(x, y, RCON[step % 5]);
            x.* ^= step ^ k.w[2 * (step % 2)];
            y.* ^= step ^ k.w[2 * (step % 2) + 1];
            if (step == 0) break;
        }
    }

    /// Encrypt a 64-bit value using a key k
    pub fn encrypt64(in: u64, k: Key) u64 {
        var x = @truncate(u32, in);
        var y = @truncate(u32, in >> 32);
        _encrypt(&x, &y, k);
        return @as(u64, x) | (@as(u64, y) << 32);
    }

    /// Decrypt a 64-bit value using a key k
    pub fn decrypt64(in: u64, k: Key) u64 {
        var x = @truncate(u32, in);
        var y = @truncate(u32, in >> 32);
        _decrypt(&x, &y, k);
        return @as(u64, x) | (@as(u64, y) << 32);
    }

    /// Encrypt a 32-bit value using a key k
    pub fn encrypt32(in: [2]u32, k: Key) [2]u32 {
        var out = in;
        _encrypt(&out[0], &out[1], k);
        return out;
    }

    /// Decrypt a 32-bit value using a key k
    pub fn decrypt32(in: [2]u32, k: Key) [2]u32 {
        var out = in;
        _decrypt(&out[0], &out[1], k);
        return out;
    }

    /// Encrypt 8 bytes using a key k
    pub fn encrypt(in: [8]u8, k: Key) [8]u8 {
        var x = mem.readIntLittle(u32, in[0..4]);
        var y = mem.readIntLittle(u32, in[4..8]);
        _encrypt(&x, &y, k);
        var out: [8]u8 = undefined;
        mem.writeIntLittle(u32, out[0..4], x);
        mem.writeIntLittle(u32, out[4..8], y);
        return out;
    }

    /// Decrypt 8 bytes using a key k
    pub fn decrypt(in: [8]u8, k: Key) [8]u8 {
        var x = mem.readIntLittle(u32, in[0..4]);
        var y = mem.readIntLittle(u32, in[4..8]);
        _decrypt(&x, &y, k);
        var out: [8]u8 = undefined;
        mem.writeIntLittle(u32, out[0..4], x);
        mem.writeIntLittle(u32, out[4..8], y);
        return out;
    }
};

test "CRAX-S test" {
    const k = CraxS.Key.init([_]u8{0x42} ** 16);

    const in64: u64 = 0x0123456789abcdef;
    const e64 = CraxS.encrypt64(in64, k);
    const d64 = CraxS.decrypt64(e64, k);
    testing.expectEqual(e64, 0x5bcff61869b506ac);
    testing.expectEqual(d64, in64);

    const in32 = [2]u32{ 0x123456, 0xabcdef };
    const e32 = CraxS.encrypt32(in32, k);
    const d32 = CraxS.decrypt32(e32, k);
    testing.expectEqual(d32, in32);

    const m = "12345678".*;
    const em = CraxS.encrypt(m, k);
    const de = CraxS.decrypt(em, k);
    testing.expectEqual(de, m);
}
