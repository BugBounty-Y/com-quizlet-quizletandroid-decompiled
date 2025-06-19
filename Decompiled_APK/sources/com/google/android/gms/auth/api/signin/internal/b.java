package com.google.android.gms.auth.api.signin.internal;

import android.util.Log;
import androidx.appcompat.widget.C0122z;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.u;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/* loaded from: classes2.dex */
public final class b implements Runnable {
    public static final C0122z c = new C0122z("RevokeAccessOperation", new String[0]);
    public final String a;
    public final com.google.android.gms.common.api.internal.j b;

    public b(String str) {
        u.e(str);
        this.a = str;
        this.b = new com.google.android.gms.common.api.internal.j(null);
    }

    @Override // java.lang.Runnable
    public final void run() throws IOException {
        C0122z c0122z = c;
        Status status = Status.g;
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL("https://accounts.google.com/o/oauth2/revoke?token=" + this.a).openConnection();
            httpURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            int responseCode = httpURLConnection.getResponseCode();
            if (responseCode == 200) {
                status = Status.e;
            } else {
                c0122z.getClass();
                Log.e((String) c0122z.c, ((String) c0122z.d).concat("Unable to revoke access!"));
            }
            String str = "Response Code: " + responseCode;
            if (c0122z.b <= 3) {
                ((String) c0122z.d).concat(str);
            }
        } catch (IOException e) {
            String strConcat = "IOException when revoking access: ".concat(String.valueOf(e.toString()));
            c0122z.getClass();
            Log.e((String) c0122z.c, ((String) c0122z.d).concat(strConcat));
        } catch (Exception e2) {
            String strConcat2 = "Exception when revoking access: ".concat(String.valueOf(e2.toString()));
            c0122z.getClass();
            Log.e((String) c0122z.c, ((String) c0122z.d).concat(strConcat2));
        }
        this.b.setResult(status);
    }
}
