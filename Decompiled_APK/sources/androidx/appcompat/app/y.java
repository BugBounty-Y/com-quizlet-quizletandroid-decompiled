package androidx.appcompat.app;

import android.content.Context;
import android.content.IntentFilter;
import android.hardware.camera2.CameraDevice;
import android.os.Bundle;
import android.os.IBinder;
import android.view.MenuItem;
import androidx.collection.V;
import androidx.core.view.AbstractC1047f0;
import com.facebook.internal.C1549d;
import com.google.android.gms.dynamic.RemoteCreator$RemoteCreatorException;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2457os;
import com.google.android.gms.internal.ads.AbstractC2543qs;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2313ld;
import com.google.android.gms.internal.ads.Fi;
import com.google.android.gms.internal.ads.InterfaceC2356md;
import com.google.android.gms.internal.ads.InterfaceC2399nd;
import com.google.android.gms.internal.ads.Qv;
import com.google.android.gms.internal.ads.Ts;
import com.quizlet.quizletandroid.R;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.AEADBadTagException;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class y {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public y(Fi fi, com.google.android.gms.ads.internal.util.C c) {
        this.a = 7;
        this.c = fi;
        this.b = c;
    }

    public void c() {
        C1549d c1549d = (C1549d) this.b;
        if (c1549d != null) {
            try {
                ((B) this.c).k.unregisterReceiver(c1549d);
            } catch (IllegalArgumentException unused) {
            }
            this.b = null;
        }
    }

    public abstract IntentFilter d();

    public abstract int[] e(int i);

    public abstract int f();

    public com.quizlet.qutils.string.g g(int i) {
        Object[] args = new Object[0];
        Intrinsics.checkNotNullParameter(args, "args");
        return new com.quizlet.qutils.string.f(R.string.empty, C4933y.P(args));
    }

    public MenuItem h(MenuItem menuItem) {
        if (!(menuItem instanceof androidx.core.internal.view.a)) {
            return menuItem;
        }
        androidx.core.internal.view.a aVar = (androidx.core.internal.view.a) menuItem;
        if (((V) this.c) == null) {
            this.c = new V(0);
        }
        MenuItem menuItem2 = (MenuItem) ((V) this.c).get(aVar);
        if (menuItem2 != null) {
            return menuItem2;
        }
        androidx.appcompat.view.menu.u uVar = new androidx.appcompat.view.menu.u((Context) this.b, aVar);
        ((V) this.c).put(aVar, uVar);
        return uVar;
    }

    public int[] i(int i, int i2) {
        if (i < 0 || i2 < 0 || i == i2) {
            return null;
        }
        int[] iArr = (int[]) this.c;
        iArr[0] = i;
        iArr[1] = i2;
        return iArr;
    }

    public abstract Object j(IBinder iBinder);

    public Object k(Context context) throws RemoteCreator$RemoteCreatorException {
        if (this.c == null) {
            com.google.android.gms.common.internal.u.h(context);
            Context contextA = com.google.android.gms.common.d.a(context);
            if (contextA == null) {
                throw new RemoteCreator$RemoteCreatorException("Could not get remote context.");
            }
            try {
                this.c = j((IBinder) contextA.getClassLoader().loadClass((String) this.b).newInstance());
            } catch (ClassNotFoundException e) {
                throw new RemoteCreator$RemoteCreatorException("Could not load creator class.", e);
            } catch (IllegalAccessException e2) {
                throw new RemoteCreator$RemoteCreatorException("Could not access creator.", e2);
            } catch (InstantiationException e3) {
                throw new RemoteCreator$RemoteCreatorException("Could not instantiate creator.", e3);
            }
        }
        return this.c;
    }

    public String l() {
        String str = (String) this.b;
        if (str != null) {
            return str;
        }
        Intrinsics.m("text");
        throw null;
    }

    public abstract com.quizlet.qutils.string.g m(int i);

    public abstract void n();

    public abstract int[] o(int i);

    public void p() {
        c();
        IntentFilter intentFilterD = d();
        if (intentFilterD.countActions() == 0) {
            return;
        }
        if (((C1549d) this.b) == null) {
            this.b = new C1549d(this, 1);
        }
        ((B) this.c).k.registerReceiver((C1549d) this.b, intentFilterD);
    }

    public abstract AbstractC1047f0 q(int i, byte[] bArr);

    public byte[] r(ByteBuffer byteBuffer, byte[] bArr, byte[] bArr2) throws GeneralSecurityException {
        if (byteBuffer.remaining() < 16) {
            throw new GeneralSecurityException("ciphertext too short");
        }
        int iPosition = byteBuffer.position();
        byte[] bArr3 = new byte[16];
        byteBuffer.position(byteBuffer.limit() - 16);
        byteBuffer.get(bArr3);
        byteBuffer.position(iPosition);
        byteBuffer.limit(byteBuffer.limit() - 16);
        if (bArr2 == null) {
            bArr2 = new byte[0];
        }
        try {
            byte[] bArr4 = new byte[32];
            ((AbstractC1047f0) this.c).Q(0, bArr).get(bArr4);
            int length = bArr2.length;
            int i = length & 15;
            int i2 = i == 0 ? length : (length + 16) - i;
            int iRemaining = byteBuffer.remaining();
            int i3 = iRemaining % 16;
            int i4 = (i3 == 0 ? iRemaining : (iRemaining + 16) - i3) + i2;
            ByteBuffer byteBufferOrder = ByteBuffer.allocate(i4 + 16).order(ByteOrder.LITTLE_ENDIAN);
            byteBufferOrder.put(bArr2);
            byteBufferOrder.position(i2);
            byteBufferOrder.put(byteBuffer);
            byteBufferOrder.position(i4);
            byteBufferOrder.putLong(length);
            byteBufferOrder.putLong(iRemaining);
            if (!MessageDigest.isEqual(AbstractC2543qs.l(bArr4, byteBufferOrder.array()), bArr3)) {
                throw new GeneralSecurityException("invalid MAC");
            }
            byteBuffer.position(iPosition);
            AbstractC1047f0 abstractC1047f0 = (AbstractC1047f0) this.b;
            abstractC1047f0.getClass();
            ByteBuffer byteBufferAllocate = ByteBuffer.allocate(byteBuffer.remaining());
            if (bArr.length != abstractC1047f0.M()) {
                throw new GeneralSecurityException(android.support.v4.media.session.a.f(abstractC1047f0.M(), "The nonce length (in bytes) must be "));
            }
            int iRemaining2 = byteBuffer.remaining();
            int i5 = iRemaining2 / 64;
            for (int i6 = 0; i6 < i5 + 1; i6++) {
                ByteBuffer byteBufferQ = abstractC1047f0.Q(abstractC1047f0.a + i6, bArr);
                if (i6 == i5) {
                    AbstractC2457os.j(byteBufferAllocate, byteBuffer, byteBufferQ, iRemaining2 % 64);
                } else {
                    AbstractC2457os.j(byteBufferAllocate, byteBuffer, byteBufferQ, 64);
                }
            }
            return byteBufferAllocate.array();
        } catch (GeneralSecurityException e) {
            throw new AEADBadTagException(e.toString());
        }
    }

    public void s() {
        ((C2313ld) this.b).d(new Exception());
    }

    public void t(String str, Throwable th) {
        ((C2313ld) this.b).d(th);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.J7)).booleanValue()) {
            com.google.android.gms.ads.internal.j.C.h.g(str, th);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x00bc  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00c3  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00e4  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0134 A[LOOP:1: B:16:0x0051->B:68:0x0134, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0140 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String toString() {
        /*
            Method dump skipped, instructions count: 334
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.y.toString():java.lang.String");
    }

    public void u(InterfaceC2399nd interfaceC2399nd, InterfaceC2356md interfaceC2356md) {
        Fi fi = new Fi(11, interfaceC2399nd, interfaceC2356md);
        C2313ld c2313ld = (C2313ld) this.b;
        c2313ld.a(new Qv(0, c2313ld, fi), AbstractC2270kd.g);
    }

    public /* synthetic */ y(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public y(byte[] bArr) throws GeneralSecurityException {
        this.a = 8;
        if (AbstractC1981ds.j(1)) {
            this.b = q(1, bArr);
            this.c = q(0, bArr);
            return;
        }
        throw new GeneralSecurityException("Can not use ChaCha20Poly1305 in FIPS-mode.");
    }

    public y(Object obj, List items) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(items, "items");
        this.b = items;
        this.c = obj;
        if (items.size() != 2 && items.size() != 3) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(items.size(), "QSegmentedControl only supports 2 or 3 items. Found: ").toString());
        }
        if (items.contains(obj)) {
            return;
        }
        throw new IllegalStateException(("Selected Item " + obj + " is not in items: " + items).toString());
    }

    public y(String content, List parameters) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        this.b = content;
        this.c = parameters;
    }

    public y(Bundle data, String type) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(data, "data");
        this.b = type;
        this.c = data;
    }

    public y(CameraDevice cameraDevice, com.google.android.gms.auth.api.signin.internal.h hVar) {
        this.a = 2;
        cameraDevice.getClass();
        this.b = cameraDevice;
        this.c = hVar;
    }

    public y(int i) {
        this.a = i;
        switch (i) {
            case 6:
                C2313ld c2313ld = new C2313ld();
                this.b = c2313ld;
                this.c = new AtomicInteger(0);
                Ts ts = new Ts(this, 13);
                c2313ld.a(new Qv(0, c2313ld, ts), AbstractC2270kd.g);
                break;
            default:
                this.c = new int[2];
                break;
        }
    }

    public y(B b) {
        this.a = 0;
        this.c = b;
    }
}
