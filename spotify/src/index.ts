export interface Env {
  SPOTIFY_CLIENT_ID: string;
  SPOTIFY_CLIENT_SECRET: string;
  SPOTIFY_REFRESH_TOKEN: string;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext
  ): Promise<Response> {
    if (request.method === "OPTIONS") {
      return this.handleOptions(request);
    }
    const auth: { access_token: string } = await fetch(
      "https://accounts.spotify.com/api/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${btoa(
            `${env.SPOTIFY_CLIENT_ID}:${env.SPOTIFY_CLIENT_SECRET}`
          )}`,
        },
        body: `grant_type=refresh_token&refresh_token=${env.SPOTIFY_REFRESH_TOKEN}&client_id=${env.SPOTIFY_CLIENT_ID}`,
      }
    ).then((res) => res.json());

    const data: SpotifyResponse = (await fetch(
      "https://api.spotify.com/v1/me/player/currently-playing?market=ES",
      {
        headers: {
          Authorization: `Bearer ${auth.access_token}`,
        },
      }
    )
      .then((res) => res.json())
      .catch((err) => {
        return {
          error: {
            status: 404,
            message: "No music playing",
            error: {
              message: err.message,
              status: err.status,
              stack: err.stack,
            },
          },
        };
      })) as SpotifyResponse;

    const response = Response.json(
      data.error
        ? {
            error: data.error,
          }
        : {
            title: data.item.name,
            artist: data.item.artists[0].name,
            album: data.item.album.name,
            albumArt: data.item.album.images[2].url,
            link: data.item.external_urls.spotify,
          },
      {
        status: data.error ? data.error.status : 200,
      }
    );

    response.headers.set("Access-Control-Allow-Origin", "*");
    response.headers.set(
      "Access-Control-Allow-Methods",
      "GET, HEAD, POST, PUT, OPTIONS"
    );
    response.headers.set("Access-Control-Allow-Headers", "Content-Type");

    return response;
  },
  async handleOptions(request: Request): Promise<Response> {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
      "Access-Control-Max-Age": "86400",
    };
    if (
      request.headers.get("Origin") !== null &&
      request.headers.get("Access-Control-Request-Method") !== null &&
      request.headers.get("Access-Control-Request-Headers") !== null
    ) {
      // Handle CORS preflight requests.
      return new Response(null, {
        headers: {
          ...corsHeaders,
          "Access-Control-Allow-Headers": request.headers.get(
            "Access-Control-Request-Headers"
          ) as string,
        },
      });
    } else {
      // Handle standard OPTIONS request.
      return new Response(null, {
        headers: {
          Allow: "GET, HEAD, POST, OPTIONS",
        },
      });
    }
  },
};

type SpotifyResponse = {
  timestamp: number;
  context: {
    external_urls: {
      spotify: string;
    };
    href: string;
    type: string;
    uri: string;
  };
  progress_ms: number;
  item: {
    album: {
      album_group: string;
      album_type: string;
      artists: {
        external_urls: {
          spotify: string;
        };
        href: string;
        id: string;
        name: string;
        type: string;
        uri: string;
      }[];
      external_urls: {
        spotify: string;
      };
      href: string;
      id: string;
      images: {
        height: number;
        url: string;
        width: number;
      }[];
      is_playable: boolean;
      name: string;
      release_date: string;
      release_date_precision: string;
      total_tracks: number;
      type: string;
      uri: string;
    };
    artists: {
      external_urls: {
        spotify: string;
      };
      href: string;
      id: string;
      name: string;
      type: string;
      uri: string;
    }[];
    disc_number: number;
    duration_ms: number;
    explicit: boolean;
    external_ids: {
      isrc: string;
    };
    external_urls: {
      spotify: string;
    };
    href: string;
    id: string;
    is_local: boolean;
    is_playable: boolean;
    name: string;
    popularity: number;
    preview_url: string | null;
    track_number: number;
    type: string;
    uri: string;
  };
} & {
  error: {
    status: number;
    message: string;
    error: any;
  };
};
