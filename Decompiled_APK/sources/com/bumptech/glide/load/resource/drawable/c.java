package com.bumptech.glide.load.resource.drawable;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.text.TextUtils;
import com.amazon.device.ads.DtbConstants;
import com.bumptech.glide.load.engine.v;
import com.bumptech.glide.load.g;
import com.bumptech.glide.load.h;
import com.bumptech.glide.load.j;
import com.google.android.gms.internal.mlkit_vision_common.B;
import java.util.List;

/* loaded from: classes.dex */
public class c implements j {
    public static final g b = new g("com.bumptech.glide.load.resource.bitmap.Downsampler.Theme", null, g.e);
    public final Context a;

    public c(Context context) {
        this.a = context.getApplicationContext();
    }

    @Override // com.bumptech.glide.load.j
    public final boolean a(Object obj, h hVar) {
        String scheme = ((Uri) obj).getScheme();
        return scheme != null && scheme.equals("android.resource");
    }

    @Override // com.bumptech.glide.load.j
    public final /* bridge */ /* synthetic */ v b(Object obj, int i, int i2, h hVar) {
        return c((Uri) obj, hVar);
    }

    public final v c(Uri uri, h hVar) throws PackageManager.NameNotFoundException, NumberFormatException {
        Context contextCreatePackageContext;
        int identifier;
        String authority = uri.getAuthority();
        if (TextUtils.isEmpty(authority)) {
            throw new IllegalStateException("Package name for " + uri + " is null or empty");
        }
        Context context = this.a;
        if (authority.equals(context.getPackageName())) {
            contextCreatePackageContext = context;
        } else {
            try {
                contextCreatePackageContext = context.createPackageContext(authority, 0);
            } catch (PackageManager.NameNotFoundException e) {
                if (!authority.contains(context.getPackageName())) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.h(uri, "Failed to obtain context or unrecognized Uri format for: "), e);
                }
            }
        }
        List<String> pathSegments = uri.getPathSegments();
        if (pathSegments.size() == 2) {
            List<String> pathSegments2 = uri.getPathSegments();
            String authority2 = uri.getAuthority();
            String str = pathSegments2.get(0);
            String str2 = pathSegments2.get(1);
            identifier = contextCreatePackageContext.getResources().getIdentifier(str2, str, authority2);
            if (identifier == 0) {
                identifier = Resources.getSystem().getIdentifier(str2, str, DtbConstants.NATIVE_OS_NAME);
            }
            if (identifier == 0) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.h(uri, "Failed to find resource id for: "));
            }
        } else {
            if (pathSegments.size() != 1) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.h(uri, "Unrecognized Uri format: "));
            }
            try {
                identifier = Integer.parseInt(uri.getPathSegments().get(0));
            } catch (NumberFormatException e2) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.h(uri, "Unrecognized Uri format: "), e2);
            }
        }
        Resources.Theme theme = authority.equals(context.getPackageName()) ? (Resources.Theme) hVar.c(b) : null;
        Drawable drawableD = theme == null ? B.d(context, contextCreatePackageContext, identifier, null) : B.d(context, context, identifier, theme);
        if (drawableD != null) {
            return new b(drawableD, 0);
        }
        return null;
    }
}
