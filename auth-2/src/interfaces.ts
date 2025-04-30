export interface IUser {
    id: string;
    email: string;
    password?: string;
    google_id?: string;
    role: 'admin' | 'user';
}

export interface IToken {
    id: string;
    user_id: string;
    jti: string;
    revoked: boolean;
    expires_at: Date;
    created_at: Date;
}

export interface AppListItem {
    id: string;
    displayName: string;
    redirect_url: string;
    admin_only?: boolean;
}