/**
 * MeshWall Offline Canvas Tile Layer
 * Draws a dark background with subtle grid lines - no external tile servers.
 */
L.TileLayer.Offline = L.TileLayer.Canvas.extend({
    createTile: function(coords, done) {
        var tile = document.createElement('canvas');
        tile.width = this.options.tileSize;
        tile.height = this.options.tileSize;
        var ctx = tile.getContext('2d');

        // Dark background
        ctx.fillStyle = '#0a0f0a';
        ctx.fillRect(0, 0, tile.width, tile.height);

        // Grid lines (very faint green)
        ctx.strokeStyle = 'rgba(0, 255, 0, 0.05)';
        ctx.lineWidth = 0.5;

        var step = 64; // grid spacing in pixels
        for (var x = 0; x < tile.width; x += step) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, tile.height);
            ctx.stroke();
        }
        for (var y = 0; y < tile.height; y += step) {
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(tile.width, y);
            ctx.stroke();
        }

        // Optional: border around the tile for a subtle hex effect
        ctx.strokeStyle = 'rgba(0, 255, 0, 0.1)';
        ctx.strokeRect(0, 0, tile.width, tile.height);

        done(null, tile);
    }
});

L.tileLayer.offline = function(options) {
    return new L.TileLayer.Offline(options);
};