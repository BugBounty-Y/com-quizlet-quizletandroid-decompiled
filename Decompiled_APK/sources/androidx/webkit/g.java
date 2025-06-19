package androidx.webkit;

import android.net.Uri;
import android.util.Log;
import android.webkit.WebResourceResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.zip.GZIPInputStream;

/* loaded from: classes.dex */
public final class g {
    public final ArrayList a;

    public g(ArrayList arrayList) {
        this.a = arrayList;
    }

    public final WebResourceResponse a(Uri uri) throws IOException {
        File file;
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            f fVar = (f) it2.next();
            fVar.getClass();
            boolean zEquals = uri.getScheme().equals("http");
            String str = fVar.b;
            e eVar = (!zEquals && (uri.getScheme().equals("http") || uri.getScheme().equals("https")) && uri.getAuthority().equals(fVar.a) && uri.getPath().startsWith(str)) ? fVar.c : null;
            if (eVar != null) {
                String strReplaceFirst = uri.getPath().replaceFirst(str, "");
                File file2 = eVar.a;
                try {
                    String strA = androidx.webkit.internal.i.a(file2);
                    String canonicalPath = new File(file2, strReplaceFirst).getCanonicalPath();
                    file = canonicalPath.startsWith(strA) ? new File(canonicalPath) : null;
                } catch (IOException e) {
                    Log.e("WebViewAssetLoader", "Error opening the requested path: " + strReplaceFirst, e);
                }
                if (file == null) {
                    Log.e("WebViewAssetLoader", String.format("The requested file: %s is outside the mounted directory: %s", strReplaceFirst, file2));
                    return new WebResourceResponse(null, null, null);
                }
                InputStream fileInputStream = new FileInputStream(file);
                if (file.getPath().endsWith(".svgz")) {
                    fileInputStream = new GZIPInputStream(fileInputStream);
                }
                return new WebResourceResponse(androidx.webkit.internal.i.b(strReplaceFirst), null, fileInputStream);
            }
        }
        return null;
    }
}
