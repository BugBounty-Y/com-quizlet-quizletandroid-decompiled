package androidx.appcompat.widget;

import android.graphics.Bitmap;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.facebook.GraphRequest$ParcelableResourceWithMimeType;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import okhttp3.C5081j;
import okhttp3.C5082k;

/* loaded from: classes.dex */
public final class o1 implements com.facebook.s {
    public boolean a = true;
    public boolean b;
    public Object c;
    public Object d;

    @Override // com.facebook.s
    public void a(String key, String value) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        h(key, null, null);
        k("%s", value);
        m();
        com.facebook.internal.A a = (com.facebook.internal.A) this.d;
        if (a != null) {
            a.a(value, "    " + key);
        }
    }

    public C5082k b() {
        return new C5082k(this.a, this.b, (String[]) this.c, (String[]) this.d);
    }

    public void c(String... cipherSuites) {
        Intrinsics.checkNotNullParameter(cipherSuites, "cipherSuites");
        if (!this.a) {
            throw new IllegalArgumentException("no cipher suites for cleartext connections");
        }
        if (cipherSuites.length == 0) {
            throw new IllegalArgumentException("At least one cipher suite is required");
        }
        this.c = (String[]) cipherSuites.clone();
    }

    public void d(C5081j... cipherSuites) {
        Intrinsics.checkNotNullParameter(cipherSuites, "cipherSuites");
        if (!this.a) {
            throw new IllegalArgumentException("no cipher suites for cleartext connections");
        }
        ArrayList arrayList = new ArrayList(cipherSuites.length);
        for (C5081j c5081j : cipherSuites) {
            arrayList.add(c5081j.a);
        }
        String[] strArr = (String[]) arrayList.toArray(new String[0]);
        c((String[]) Arrays.copyOf(strArr, strArr.length));
    }

    public void e(String... tlsVersions) {
        Intrinsics.checkNotNullParameter(tlsVersions, "tlsVersions");
        if (!this.a) {
            throw new IllegalArgumentException("no TLS versions for cleartext connections");
        }
        if (tlsVersions.length == 0) {
            throw new IllegalArgumentException("At least one TLS version is required");
        }
        this.d = (String[]) tlsVersions.clone();
    }

    public void f(okhttp3.L... tlsVersions) {
        Intrinsics.checkNotNullParameter(tlsVersions, "tlsVersions");
        if (!this.a) {
            throw new IllegalArgumentException("no TLS versions for cleartext connections");
        }
        ArrayList arrayList = new ArrayList(tlsVersions.length);
        for (okhttp3.L l : tlsVersions) {
            arrayList.add(l.a);
        }
        String[] strArr = (String[]) arrayList.toArray(new String[0]);
        e((String[]) Arrays.copyOf(strArr, strArr.length));
    }

    public void g(String format, Object... args) throws IOException {
        Intrinsics.checkNotNullParameter(format, "format");
        Intrinsics.checkNotNullParameter(args, "args");
        FilterOutputStream filterOutputStream = (FilterOutputStream) this.c;
        if (this.b) {
            Locale locale = Locale.US;
            Object[] objArrCopyOf = Arrays.copyOf(args, args.length);
            String str = String.format(locale, format, Arrays.copyOf(objArrCopyOf, objArrCopyOf.length));
            Intrinsics.checkNotNullExpressionValue(str, "format(locale, format, *args)");
            String strEncode = URLEncoder.encode(str, "UTF-8");
            Intrinsics.checkNotNullExpressionValue(strEncode, "encode(String.format(Loc… format, *args), \"UTF-8\")");
            byte[] bytes = strEncode.getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            filterOutputStream.write(bytes);
            return;
        }
        if (this.a) {
            Charset charset = Charsets.UTF_8;
            byte[] bytes2 = "--".getBytes(charset);
            Intrinsics.checkNotNullExpressionValue(bytes2, "this as java.lang.String).getBytes(charset)");
            filterOutputStream.write(bytes2);
            byte[] bytes3 = com.facebook.t.j.getBytes(charset);
            Intrinsics.checkNotNullExpressionValue(bytes3, "this as java.lang.String).getBytes(charset)");
            filterOutputStream.write(bytes3);
            byte[] bytes4 = "\r\n".getBytes(charset);
            Intrinsics.checkNotNullExpressionValue(bytes4, "this as java.lang.String).getBytes(charset)");
            filterOutputStream.write(bytes4);
            this.a = false;
        }
        Object[] objArrCopyOf2 = Arrays.copyOf(args, args.length);
        byte[] bytes5 = androidx.compose.animation.d0.s(objArrCopyOf2, objArrCopyOf2.length, format, "format(format, *args)").getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes5, "this as java.lang.String).getBytes(charset)");
        filterOutputStream.write(bytes5);
    }

    public void h(String str, String str2, String str3) throws IOException {
        if (this.b) {
            byte[] bytes = androidx.compose.animation.d0.s(new Object[]{str}, 1, "%s=", "format(format, *args)").getBytes(Charsets.UTF_8);
            Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
            ((FilterOutputStream) this.c).write(bytes);
            return;
        }
        g("Content-Disposition: form-data; name=\"%s\"", str);
        if (str2 != null) {
            g("; filename=\"%s\"", str2);
        }
        k("", new Object[0]);
        if (str3 != null) {
            k("%s: %s", "Content-Type", str3);
        }
        k("", new Object[0]);
    }

    public void i(Uri contentUri, String key, String str) throws IOException {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(contentUri, "contentUri");
        if (str == null) {
            str = "content/unknown";
        }
        h(key, key, str);
        int iJ = com.facebook.internal.J.j(com.facebook.o.a().getContentResolver().openInputStream(contentUri), (FilterOutputStream) this.c);
        k("", new Object[0]);
        m();
        com.facebook.internal.A a = (com.facebook.internal.A) this.d;
        String strD = AbstractC0147y.d("    ", key);
        String str2 = String.format(Locale.ROOT, "<Data: %d>", Arrays.copyOf(new Object[]{Integer.valueOf(iJ)}, 1));
        Intrinsics.checkNotNullExpressionValue(str2, "format(locale, format, *args)");
        a.a(str2, strD);
    }

    public void j(String key, ParcelFileDescriptor descriptor, String str) throws IOException {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(descriptor, "descriptor");
        if (str == null) {
            str = "content/unknown";
        }
        h(key, key, str);
        int iJ = com.facebook.internal.J.j(new ParcelFileDescriptor.AutoCloseInputStream(descriptor), (FilterOutputStream) this.c);
        k("", new Object[0]);
        m();
        com.facebook.internal.A a = (com.facebook.internal.A) this.d;
        String strD = AbstractC0147y.d("    ", key);
        String str2 = String.format(Locale.ROOT, "<Data: %d>", Arrays.copyOf(new Object[]{Integer.valueOf(iJ)}, 1));
        Intrinsics.checkNotNullExpressionValue(str2, "format(locale, format, *args)");
        a.a(str2, strD);
    }

    public void k(String format, Object... args) throws IOException {
        Intrinsics.checkNotNullParameter(format, "format");
        Intrinsics.checkNotNullParameter(args, "args");
        g(format, Arrays.copyOf(args, args.length));
        if (this.b) {
            return;
        }
        g("\r\n", new Object[0]);
    }

    public void l(String key, Object obj, com.facebook.t tVar) {
        Intrinsics.checkNotNullParameter(key, "key");
        FilterOutputStream filterOutputStream = (FilterOutputStream) this.c;
        String str = com.facebook.t.j;
        if (assistantMode.utils.studiableMetadata.b.N(obj)) {
            a(key, assistantMode.utils.studiableMetadata.b.C(obj));
            return;
        }
        boolean z = obj instanceof Bitmap;
        com.facebook.internal.A a = (com.facebook.internal.A) this.d;
        if (z) {
            Bitmap bitmap = (Bitmap) obj;
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(bitmap, "bitmap");
            h(key, key, "image/png");
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, filterOutputStream);
            k("", new Object[0]);
            m();
            a.a("<Image>", "    " + key);
            return;
        }
        if (obj instanceof byte[]) {
            byte[] bytes = (byte[]) obj;
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(bytes, "bytes");
            h(key, key, "content/unknown");
            filterOutputStream.write(bytes);
            k("", new Object[0]);
            m();
            String str2 = String.format(Locale.ROOT, "<Data: %d>", Arrays.copyOf(new Object[]{Integer.valueOf(bytes.length)}, 1));
            Intrinsics.checkNotNullExpressionValue(str2, "format(locale, format, *args)");
            a.a(str2, "    " + key);
            return;
        }
        if (obj instanceof Uri) {
            i((Uri) obj, key, null);
            return;
        }
        if (obj instanceof ParcelFileDescriptor) {
            j(key, (ParcelFileDescriptor) obj, null);
            return;
        }
        if (!(obj instanceof GraphRequest$ParcelableResourceWithMimeType)) {
            throw new IllegalArgumentException("value is not a supported type.");
        }
        GraphRequest$ParcelableResourceWithMimeType graphRequest$ParcelableResourceWithMimeType = (GraphRequest$ParcelableResourceWithMimeType) obj;
        Parcelable parcelable = graphRequest$ParcelableResourceWithMimeType.b;
        boolean z2 = parcelable instanceof ParcelFileDescriptor;
        String str3 = graphRequest$ParcelableResourceWithMimeType.a;
        if (z2) {
            j(key, (ParcelFileDescriptor) parcelable, str3);
        } else {
            if (!(parcelable instanceof Uri)) {
                throw new IllegalArgumentException("value is not a supported type.");
            }
            i((Uri) parcelable, key, str3);
        }
    }

    public void m() throws IOException {
        if (!this.b) {
            k("--%s", com.facebook.t.j);
            return;
        }
        byte[] bytes = "&".getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(bytes, "this as java.lang.String).getBytes(charset)");
        ((FilterOutputStream) this.c).write(bytes);
    }
}
