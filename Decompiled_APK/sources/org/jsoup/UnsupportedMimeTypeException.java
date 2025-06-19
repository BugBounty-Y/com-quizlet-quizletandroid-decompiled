package org.jsoup;

import android.support.v4.media.session.a;
import java.io.IOException;

/* loaded from: classes3.dex */
public class UnsupportedMimeTypeException extends IOException {
    @Override // java.lang.Throwable
    public final String toString() {
        return a.t(new StringBuilder(), super.toString(), ". Mimetype=null, URL=null");
    }
}
