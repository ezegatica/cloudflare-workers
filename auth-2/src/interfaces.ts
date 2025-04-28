export interface IUser {
    id: string;
    email: string;
    password?: string;
    googleId?: string;
    role: 'admin' | 'user';
}

export interface AppListItem {
    id: string;
    displayName: string;
    redirect_url: string;
    admin_only?: boolean;
}