package com.google.android.gms.internal.measurement;

import android.content.ContentProviderClient;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.RemoteException;
import android.util.Log;
import androidx.collection.C0208f;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.measurement.i2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3005i2 implements InterfaceC3025m2 {
    public static final U1 b = new U1(3);
    public final Object a;

    public /* synthetic */ C3005i2(Object obj) {
        this.a = obj;
    }

    public Object a() {
        C3068v1 c3068v1 = (C3068v1) this.a;
        ContentResolver contentResolver = c3068v1.a;
        Uri uri = c3068v1.b;
        ContentProviderClient contentProviderClientAcquireUnstableContentProviderClient = contentResolver.acquireUnstableContentProviderClient(uri);
        try {
            if (contentProviderClientAcquireUnstableContentProviderClient == null) {
                Log.w("ConfigurationContentLdr", "Unable to acquire ContentProviderClient, using default values");
                return Collections.EMPTY_MAP;
            }
            Cursor cursorQuery = contentProviderClientAcquireUnstableContentProviderClient.query(uri, C3068v1.i, null, null, null);
            try {
                if (cursorQuery == null) {
                    Log.w("ConfigurationContentLdr", "ContentProvider query returned null cursor, using default values");
                    return Collections.EMPTY_MAP;
                }
                int count = cursorQuery.getCount();
                if (count == 0) {
                    Map map = Collections.EMPTY_MAP;
                    cursorQuery.close();
                    return map;
                }
                Map c0208f = count <= 256 ? new C0208f(count) : new HashMap(count, 1.0f);
                while (cursorQuery.moveToNext()) {
                    c0208f.put(cursorQuery.getString(0), cursorQuery.getString(1));
                }
                if (cursorQuery.isAfterLast()) {
                    cursorQuery.close();
                    return c0208f;
                }
                Log.w("ConfigurationContentLdr", "Cursor read incomplete (ContentProvider dead?), using default values");
                Map map2 = Collections.EMPTY_MAP;
                cursorQuery.close();
                return map2;
            } finally {
            }
        } catch (RemoteException e) {
            Log.w("ConfigurationContentLdr", "ContentProvider query failed, using default values", e);
            return Collections.EMPTY_MAP;
        } finally {
            contentProviderClientAcquireUnstableContentProviderClient.release();
        }
    }

    public void b(int i, Object obj, InterfaceC3069v2 interfaceC3069v2) throws zzli {
        P1 p1 = (P1) this.a;
        p1.k(i, 3);
        interfaceC3069v2.d((J1) obj, p1.b);
        p1.k(i, 4);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3025m2
    public C3064u2 c(Class cls) {
        for (int i = 0; i < 2; i++) {
            InterfaceC3025m2 interfaceC3025m2 = ((InterfaceC3025m2[]) this.a)[i];
            if (interfaceC3025m2.d(cls)) {
                return interfaceC3025m2.c(cls);
            }
        }
        throw new UnsupportedOperationException("No factory is available for message type: ".concat(cls.getName()));
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3025m2
    public boolean d(Class cls) {
        for (int i = 0; i < 2; i++) {
            if (((InterfaceC3025m2[]) this.a)[i].d(cls)) {
                return true;
            }
        }
        return false;
    }

    public void e(int i, Object obj, InterfaceC3069v2 interfaceC3069v2) throws zzli {
        J1 j1 = (J1) obj;
        P1 p1 = (P1) this.a;
        p1.m((i << 3) | 2);
        p1.m(j1.a(interfaceC3069v2));
        interfaceC3069v2.d(j1, p1.b);
    }

    public C3005i2(int i) {
        switch (i) {
            case 1:
                this.a = new HashMap();
                break;
            default:
                C3054s2 c3054s2 = C3054s2.c;
                C3005i2 c3005i2 = new C3005i2(new InterfaceC3025m2[]{U1.b, b});
                Charset charset = AbstractC2980d2.a;
                this.a = c3005i2;
                break;
        }
    }

    public C3005i2(P1 p1) {
        Charset charset = AbstractC2980d2.a;
        this.a = p1;
        p1.b = this;
    }
}
