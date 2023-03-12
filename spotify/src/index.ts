export interface Env {
	SPOTIFY_TOKEN: string;
}

export default {
	async fetch(
		_request: Request,
		env: Env,
		_ctx: ExecutionContext
	): Promise<Response> {
		const data: SpotifyResponse = await fetch('https://api.spotify.com/v1/me/player/currently-playing?market=ES', {
			headers: {
				'Authorization': `Bearer ${env.SPOTIFY_TOKEN}`			
			},
		}).then((res) => res.json());
		if (!data.item){
			return Response.json({
				nothingPlaying: true,
				title: '',
				artist: '',
				album: '',
				albumArt: '',
				link: '',
			})
		}
		return Response.json({
			nothingPlaying: false,
			title: data.item.name,
			artist: data.item.artists[0].name,
			album: data.item.album.name,
			albumArt: data.item.album.images[0].url,
			link: data.item.external_urls.spotify,
		})
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
  };