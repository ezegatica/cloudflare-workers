// import { Tweet } from 'react-tweet/api'

const SYNDICATION_URL = 'https://cdn.syndication.twimg.com'

export class TwitterApiError extends Error {
  status: number
  data: any

  constructor({
    message,
    status,
    data,
  }: {
    message: string
    status: number
    data: any
  }) {
    super(message)
    this.name = 'TwitterApiError'
    this.status = status
    this.data = data
  }
}

const TWEET_ID = /^[0-9]+$/

function getToken(id: string) {
  return ((Number(id) / 1e15) * Math.PI)
    .toString(6 ** 2)
    .replace(/(0+|\.)/g, '')
}

/**
 * Fetches a tweet from the Twitter syndication API.
 */
export async function fetchTweet(
  id: string,
  fetchOptions?: RequestInit
): Promise<{ data: any; } | { tombstone: true } | { notFound: true }> {
  if (id.length > 40 || !TWEET_ID.test(id)) {
    throw new Error(`Invalid tweet id: ${id}`)
  }

  const url = new URL(`${SYNDICATION_URL}/tweet-result`)

  url.searchParams.set('id', id)
  url.searchParams.set('lang', 'en')
  url.searchParams.set('token', getToken(id))

  const res = await fetch(url.toString(), fetchOptions)
  const isJson = res.headers.get('content-type')?.includes('application/json')
  const data = isJson ? await res.json() : undefined as any

  if (res.ok) {
    if (data?.__typename === 'TweetTombstone') {
      return { tombstone: true }
    }
    return { data }
  }
  if (res.status === 404) {
    return { notFound: true }
  }

  console.log({ res, data, id, url: url.toString(), isJson})

  throw new TwitterApiError({
    message:
      typeof data?.error === 'string'
        ? data?.error
        : `Failed to fetch tweet at "${url}" with "${res.status}".`,
    status: res.status,
    data,
  })
}
