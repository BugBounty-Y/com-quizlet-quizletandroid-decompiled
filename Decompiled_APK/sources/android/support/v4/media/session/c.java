package android.support.v4.media.session;

import android.os.BadParcelableException;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

/* loaded from: classes.dex */
public abstract class c {
    static {
        Build.VERSION.CODENAME.equals("S");
    }

    public static Bundle a(Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        bundle.setClassLoader(c.class.getClassLoader());
        try {
            bundle.isEmpty();
            return bundle;
        } catch (BadParcelableException unused) {
            Log.e("MediaSessionCompat", "Could not unparcel the data.");
            return null;
        }
    }
}
