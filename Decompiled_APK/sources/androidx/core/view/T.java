package androidx.core.view;

import android.view.ContentInfo;
import android.view.View;
import java.util.Objects;

/* loaded from: classes.dex */
public abstract class T {
    public static String[] a(View view) {
        return view.getReceiveContentMimeTypes();
    }

    public static C1050h b(View view, C1050h c1050h) {
        ContentInfo contentInfoP = c1050h.a.p();
        Objects.requireNonNull(contentInfoP);
        ContentInfo contentInfoPerformReceiveContent = view.performReceiveContent(contentInfoP);
        if (contentInfoPerformReceiveContent == null) {
            return null;
        }
        return contentInfoPerformReceiveContent == contentInfoP ? c1050h : new C1050h(new com.google.android.gms.internal.instantapps.a(contentInfoPerformReceiveContent));
    }
}
