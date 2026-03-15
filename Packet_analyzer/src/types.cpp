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
        case AppType::UNACADEMY:  return "Unacademy";
        case AppType::CLOUDFLARE: return "Cloudflare";
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
    
    // YouTube (Check before Google because YouTube uses Google infra)
    if (lower_sni.find("youtube.com") != std::string::npos ||
        lower_sni.find("googlevideo.com") != std::string::npos ||
        lower_sni.find("ytimg.com") != std::string::npos ||
        lower_sni.find("youtu.be") != std::string::npos ||
        lower_sni.find("yt3.ggpht") != std::string::npos) {
        return AppType::YOUTUBE;
    }
    
    // Google
    if (lower_sni.find("google.com") != std::string::npos ||
        lower_sni.find("gstatic.com") != std::string::npos ||
        lower_sni.find("googleapis.com") != std::string::npos ||
        lower_sni.find("1e100.net") != std::string::npos ||
        lower_sni.find("ggpht") != std::string::npos ||
        lower_sni.find("gvt1") != std::string::npos) {
        return AppType::GOOGLE;
    }
    
    // Facebook/Meta
    if (lower_sni.find("facebook.com") != std::string::npos ||
        lower_sni.find("fbcdn.net") != std::string::npos ||
        lower_sni.find("messenger.com") != std::string::npos ||
        lower_sni.find("fbsbx.com") != std::string::npos ||
        lower_sni.find("meta.com") != std::string::npos) {
        return AppType::FACEBOOK;
    }
    
    // Instagram (owned by Meta)
    if (lower_sni.find("instagram.com") != std::string::npos ||
        lower_sni.find("cdninstagram.com") != std::string::npos) {
        return AppType::INSTAGRAM;
    }
    
    // WhatsApp (owned by Meta)
    if (lower_sni.find("whatsapp.com") != std::string::npos ||
        lower_sni.find("whatsapp.net") != std::string::npos ||
        lower_sni.find("wa.me") != std::string::npos) {
        return AppType::WHATSAPP;
    }
    
    // Twitter/X (Fix t.co bug)
    if (lower_sni.find("twitter.com") != std::string::npos ||
        lower_sni.find("twimg.com") != std::string::npos ||
        lower_sni.find("x.com") != std::string::npos ||
        (lower_sni == "t.co" || lower_sni.find(".t.co") != std::string::npos)) {
        return AppType::TWITTER;
    }
    
    // Netflix
    if (lower_sni.find("netflix") != std::string::npos ||
        lower_sni.find("nflxvideo") != std::string::npos ||
        lower_sni.find("nflximg") != std::string::npos) {
        return AppType::NETFLIX;
    }
    
    // Amazon
    if (lower_sni.find("amazon") != std::string::npos ||
        lower_sni.find("amazonaws") != std::string::npos ||
        lower_sni.find("cloudfront") != std::string::npos ||
        lower_sni.find("aws") != std::string::npos) {
        return AppType::AMAZON;
    }
    
    // Microsoft
    if (lower_sni.find("microsoft") != std::string::npos ||
        lower_sni.find("msn.com") != std::string::npos ||
        lower_sni.find("office") != std::string::npos ||
        lower_sni.find("azure") != std::string::npos ||
        lower_sni.find("live.com") != std::string::npos ||
        lower_sni.find("outlook") != std::string::npos ||
        lower_sni.find("bing") != std::string::npos) {
        return AppType::MICROSOFT;
    }
    
    // Apple
    if (lower_sni.find("apple") != std::string::npos ||
        lower_sni.find("icloud") != std::string::npos ||
        lower_sni.find("mzstatic") != std::string::npos ||
        lower_sni.find("itunes") != std::string::npos) {
        return AppType::APPLE;
    }
    
    // Telegram
    if (lower_sni.find("telegram") != std::string::npos ||
        lower_sni.find("t.me") != std::string::npos) {
        return AppType::TELEGRAM;
    }
    
    // TikTok
    if (lower_sni.find("tiktok") != std::string::npos ||
        lower_sni.find("tiktokcdn") != std::string::npos ||
        lower_sni.find("musical.ly") != std::string::npos ||
        lower_sni.find("bytedance") != std::string::npos) {
        return AppType::TIKTOK;
    }
    
    // Spotify
    if (lower_sni.find("spotify") != std::string::npos ||
        lower_sni.find("scdn.co") != std::string::npos) {
        return AppType::SPOTIFY;
    }
    
    // Zoom
    if (lower_sni.find("zoom") != std::string::npos) {
        return AppType::ZOOM;
    }
    
    // Discord
    if (lower_sni.find("discord") != std::string::npos ||
        lower_sni.find("discordapp") != std::string::npos) {
        return AppType::DISCORD;
    }
    
    // GitHub
    if (lower_sni.find("github") != std::string::npos ||
        lower_sni.find("githubusercontent") != std::string::npos) {
        return AppType::GITHUB;
    }
    
    // LinkedIn
    if (lower_sni.find("linkedin") != std::string::npos ||
        lower_sni.find("licdn") != std::string::npos) {
        return AppType::LINKEDIN;
    }
    
    // Reddit
    if (lower_sni.find("reddit") != std::string::npos ||
        lower_sni.find("redditmedia") != std::string::npos) {
        return AppType::REDDIT;
    }
    
    // Wikipedia
    if (lower_sni.find("wikipedia") != std::string::npos ||
        lower_sni.find("wikimedia") != std::string::npos) {
        return AppType::WIKIPEDIA;
    }
    
    // Slack
    if (lower_sni.find("slack") != std::string::npos) {
        return AppType::SLACK;
    }
    
    // Microsoft Teams
    if (lower_sni.find("teams.microsoft.com") != std::string::npos ||
        lower_sni.find("teams.live.com") != std::string::npos) {
        return AppType::TEAMS;
    }
    
    // Dropbox
    if (lower_sni.find("dropbox") != std::string::npos) {
        return AppType::DROPBOX;
    }
    
    // Unacademy
    if (lower_sni.find("unacademy") != std::string::npos) {
        return AppType::UNACADEMY;
    }
    
    // Cloudflare
    if (lower_sni.find("cloudflare") != std::string::npos ||
        lower_sni.find("cf-") != std::string::npos) {
        return AppType::CLOUDFLARE;
    }
    
    // If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType::HTTPS;
}

} // namespace DPI
