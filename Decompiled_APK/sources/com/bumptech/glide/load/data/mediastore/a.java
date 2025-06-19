package com.bumptech.glide.load.data.mediastore;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.provider.MediaStore;

/* loaded from: classes.dex */
public final class a implements c {
    public static final String[] c = {"_data"};
    public static final String[] d = {"_data"};
    public final /* synthetic */ int a;
    public final ContentResolver b;

    public /* synthetic */ a(ContentResolver contentResolver, int i) {
        this.a = i;
        this.b = contentResolver;
    }

    @Override // com.bumptech.glide.load.data.mediastore.c
    public final Cursor a(Uri uri) {
        switch (this.a) {
            case 0:
                String lastPathSegment = uri.getLastPathSegment();
                return this.b.query(MediaStore.Images.Thumbnails.EXTERNAL_CONTENT_URI, c, "kind = 1 AND image_id = ?", new String[]{lastPathSegment}, null);
            default:
                String lastPathSegment2 = uri.getLastPathSegment();
                return this.b.query(MediaStore.Video.Thumbnails.EXTERNAL_CONTENT_URI, d, "kind = 1 AND video_id = ?", new String[]{lastPathSegment2}, null);
        }
    }
}
