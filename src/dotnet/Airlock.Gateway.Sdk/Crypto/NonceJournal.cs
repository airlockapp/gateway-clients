using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;

namespace Airlock.Gateway.Sdk.Crypto
{
    /// <summary>
    /// Anti-replay nonce journal. Records seen nonces and prevents replay attacks.
    /// Entries expire after a configurable TTL and are pruned on access.
    /// Adapted from the HARP reference implementation (harp-samples).
    /// </summary>
    public sealed class NonceJournal
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new();
        private readonly TimeSpan _ttl;
        private readonly string? _persistPath;
        private long _lastPrune;

        /// <summary>
        /// Create a new nonce journal.
        /// </summary>
        /// <param name="ttl">How long to keep nonces before considering them expired. Default: 15 minutes.</param>
        /// <param name="persistPath">Optional file path for persisting nonces across restarts.</param>
        public NonceJournal(TimeSpan? ttl = null, string? persistPath = null)
        {
            _ttl = ttl ?? TimeSpan.FromMinutes(15);
            _persistPath = persistPath;
            _lastPrune = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (_persistPath != null && File.Exists(_persistPath))
                LoadFromFile(_persistPath);
        }

        /// <summary>
        /// Check and record a nonce. Returns true if this is a new (unseen) nonce.
        /// Returns false if the nonce was already seen (replay detected).
        /// </summary>
        public bool TryRecord(string nonce)
        {
            MaybePrune();

            var now = DateTimeOffset.UtcNow;
            if (_seen.TryGetValue(nonce, out var existing) && now - existing < _ttl)
                return false; // replay

            _seen[nonce] = now;
            MaybePersist();
            return true;
        }

        /// <summary>
        /// Check whether a nonce has already been seen (without recording it).
        /// </summary>
        public bool HasSeen(string nonce)
        {
            if (_seen.TryGetValue(nonce, out var ts))
                return DateTimeOffset.UtcNow - ts < _ttl;
            return false;
        }

        /// <summary>The number of active (non-expired) nonces in the journal.</summary>
        public int Count
        {
            get
            {
                MaybePrune();
                return _seen.Count;
            }
        }

        private void MaybePrune()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            // Prune at most once per 60 seconds
            if (now - Interlocked.Read(ref _lastPrune) < 60) return;
            Interlocked.Exchange(ref _lastPrune, now);

            var cutoff = DateTimeOffset.UtcNow - _ttl;
            foreach (var kvp in _seen)
            {
                if (kvp.Value < cutoff)
                    _seen.TryRemove(kvp.Key, out _);
            }
        }

        private void MaybePersist()
        {
            if (_persistPath == null) return;
            try
            {
                var sb = new StringBuilder();
                foreach (var kvp in _seen)
                    sb.AppendLine($"{kvp.Key}\t{kvp.Value:O}");
                File.WriteAllText(_persistPath, sb.ToString());
            }
            catch
            {
                // Best-effort persistence — don't fail on I/O errors
            }
        }

        private void LoadFromFile(string path)
        {
            try
            {
                foreach (var line in File.ReadAllLines(path))
                {
                    var parts = line.Split('\t');
                    if (parts.Length == 2 && DateTimeOffset.TryParse(parts[1], out var ts))
                        _seen[parts[0]] = ts;
                }
            }
            catch
            {
                // Best-effort load — don't fail on I/O errors
            }
        }
    }
}
