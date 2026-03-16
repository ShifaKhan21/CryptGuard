#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::LINKEDIN:   return "LinkedIn";
        case AppType::REDDIT:     return "Reddit";
        case AppType::WIKIPEDIA:  return "Wikipedia";
        case AppType::SLACK:      return "Slack";
        case AppType::TEAMS:      return "MS Teams";
        case AppType::DROPBOX:    return "Dropbox";
        case AppType::CLOUDFLARE: return "Cloudflare";
        case AppType::UNACADEMY:  return "Unacademy";
        case AppType::SSH:        return "SSH";
        case AppType::FTP:        return "FTP";
        case AppType::SMTP:       return "SMTP";
        case AppType::POP3:       return "POP3";
        case AppType::IMAP:       return "IMAP";
        case AppType::ICMP:       return "ICMP";
        case AppType::RDP:        return "RDP";
        case AppType::NTP:        return "NTP";
        case AppType::DHCP:       return "DHCP";
        case AppType::SNMP:       return "SNMP";
        case AppType::BITTORRENT: return "BitTorrent";
        case AppType::IPV6_ICMP:  return "ICMPv6";
        default:                  return "Unknown";
    }
}

// Map SNI/domain to application type
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // Helper for domain suffix matching
    auto ends_with = [](const std::string& str, const std::string& suffix) {
        if (str.length() >= suffix.length()) {
            return (0 == str.compare(str.length() - suffix.length(), suffix.length(), suffix));
        }
        return false;
    };

    auto contains = [](const std::string& str, const std::string& sub) {
        return str.find(sub) != std::string::npos;
    };

    // YouTube (Check before Google because YouTube uses Google infra)
    if (contains(lower_sni, "youtube") || ends_with(lower_sni, "googlevideo.com") || contains(lower_sni, "ytimg")) {
        return AppType::YOUTUBE;
    }
    
    // Google
    if (contains(lower_sni, "google") || contains(lower_sni, "gstatic") || contains(lower_sni, "googleapis") || 
        ends_with(lower_sni, "1e100.net") || contains(lower_sni, "ggpht") || contains(lower_sni, "gvt1")) {
        return AppType::GOOGLE;
    }
    
    // Facebook/Meta
    if (contains(lower_sni, "facebook") || contains(lower_sni, "fbcdn") || ends_with(lower_sni, "fb.com") || 
        contains(lower_sni, "fbsbx") || ends_with(lower_sni, "meta.com")) {
        return AppType::FACEBOOK;
    }
    
    // Instagram
    if (contains(lower_sni, "instagram") || contains(lower_sni, "cdninstagram")) {
        return AppType::INSTAGRAM;
    }
    
    // WhatsApp
    if (contains(lower_sni, "whatsapp") || ends_with(lower_sni, "wa.me")) {
        return AppType::WHATSAPP;
    }
    
    // Twitter/X - Using more specific matches to avoid false positives
    if (contains(lower_sni, "twitter") || contains(lower_sni, "twimg") || 
        ends_with(lower_sni, ".x.com") || (lower_sni == "x.com") || ends_with(lower_sni, ".t.co") || (lower_sni == "t.co")) {
        return AppType::TWITTER;
    }
    
    // Netflix
    if (contains(lower_sni, "netflix") || contains(lower_sni, "nflxvideo") || contains(lower_sni, "nflxext") || contains(lower_sni, "nflximg")) {
        return AppType::NETFLIX;
    }
    
    // Amazon
    if (contains(lower_sni, "amazon") || contains(lower_sni, "amazonaws") || contains(lower_sni, "cloudfront")) {
        return AppType::AMAZON;
    }
    
    // Microsoft
    if (contains(lower_sni, "microsoft") || contains(lower_sni, "office") || contains(lower_sni, "azure") || 
        contains(lower_sni, "live.com") || contains(lower_sni, "outlook") || contains(lower_sni, "bing")) {
        return AppType::MICROSOFT;
    }
    
    // Apple
    if (contains(lower_sni, "apple") || contains(lower_sni, "icloud") || contains(lower_sni, "itunes")) {
        return AppType::APPLE;
    }
    
    // Unacademy
    if (contains(lower_sni, "unacademy") || contains(lower_sni, "uacdn")) {
        return AppType::UNACADEMY;
    }
    
    // GitHub
    if (contains(lower_sni, "github")) {
        return AppType::GITHUB;
    }

    // LinkedIn
    if (contains(lower_sni, "linkedin")) {
        return AppType::LINKEDIN;
    }

    // Cloudflare
    if (contains(lower_sni, "cloudflare")) {
        return AppType::CLOUDFLARE;
    }
    
    // If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType::HTTPS;
}

} // namespace DPI
