package androidx.webkit;

import android.content.Context;
import java.io.File;
import java.io.IOException;

/* loaded from: classes.dex */
public final class e {
    public static final String[] b = {"app_webview/", "databases/", "lib/", "shared_prefs/", "code_cache/"};
    public final File a;

    public e(Context context, File file) {
        try {
            this.a = new File(androidx.webkit.internal.i.a(file));
            if (a(context)) {
                return;
            }
            throw new IllegalArgumentException("The given directory \"" + file + "\" doesn't exist under an allowed app internal storage directory");
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to resolve the canonical path for the given directory: " + file.getPath(), e);
        }
    }

    public final boolean a(Context context) throws IOException {
        String strA = androidx.webkit.internal.i.a(this.a);
        String strA2 = androidx.webkit.internal.i.a(context.getCacheDir());
        String strA3 = androidx.webkit.internal.i.a(androidx.webkit.internal.d.e(context));
        if ((!strA.startsWith(strA2) && !strA.startsWith(strA3)) || strA.equals(strA2) || strA.equals(strA3)) {
            return false;
        }
        String[] strArr = b;
        for (int i = 0; i < 5; i++) {
            if (strA.startsWith(strA3 + strArr[i])) {
                return false;
            }
        }
        return true;
    }
}
