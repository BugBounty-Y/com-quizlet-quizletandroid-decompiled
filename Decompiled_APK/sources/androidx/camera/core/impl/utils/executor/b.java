package androidx.camera.core.impl.utils.executor;

import android.graphics.Path;
import android.graphics.PathMeasure;
import android.os.Handler;
import android.os.Looper;
import android.view.Choreographer;
import androidx.compose.ui.platform.Z;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.C2433oA;
import com.google.android.gms.internal.ads.C2505px;
import com.google.android.gms.internal.ads.C2590rx;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3224o6;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.Stack;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.crypto.Cipher;

/* loaded from: classes.dex */
public final class b extends ThreadLocal {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // java.lang.ThreadLocal
    public final Object initialValue() throws NoSuchAlgorithmException {
        Provider provider;
        SecureRandom secureRandom;
        int i = 0;
        Provider provider2 = null;
        switch (this.a) {
            case 0:
                if (Looper.myLooper() == Looper.getMainLooper()) {
                    return T.e();
                }
                if (Looper.myLooper() != null) {
                    return new e(new Handler(Looper.myLooper()));
                }
                return null;
            case 1:
                Choreographer choreographer = Choreographer.getInstance();
                Looper looperMyLooper = Looper.myLooper();
                if (looperMyLooper == null) {
                    throw new IllegalStateException("no Looper on this thread");
                }
                Z z = new Z(choreographer, AbstractC3224o6.b(looperMyLooper));
                return z.plus(z.k);
            case 2:
                return new PathMeasure();
            case 3:
                return new Path();
            case 4:
                return new Path();
            case 5:
                return new float[4];
            case 6:
                return Boolean.FALSE;
            case 7:
                return 0L;
            case 8:
                return ByteBuffer.allocate(32);
            case 9:
                try {
                    return (Cipher) C2433oA.b.a.zza("AES/GCM/NoPadding");
                } catch (GeneralSecurityException e) {
                    throw new IllegalStateException(e);
                }
            case 10:
                try {
                    Cipher cipher = (Cipher) C2433oA.b.a.zza("ChaCha20-Poly1305");
                    if (C2590rx.b(cipher)) {
                        return cipher;
                    }
                    return null;
                } catch (GeneralSecurityException unused) {
                    return null;
                }
            case 11:
                try {
                    Cipher cipher2 = (Cipher) C2433oA.b.a.zza("AES/GCM-SIV/NoPadding");
                    if (C2505px.b(cipher2)) {
                        return cipher2;
                    }
                    return null;
                } catch (GeneralSecurityException e2) {
                    throw new IllegalStateException(e2);
                }
            case 12:
                String[] strArr = AbstractC1795We.x;
                while (true) {
                    if (i < 3) {
                        provider = Security.getProvider(strArr[i]);
                        if (provider == null) {
                            i++;
                        }
                    } else {
                        provider = null;
                    }
                }
                if (provider != null) {
                    try {
                        secureRandom = SecureRandom.getInstance("SHA1PRNG", provider);
                    } catch (GeneralSecurityException unused2) {
                    }
                } else {
                    try {
                        provider2 = (Provider) Class.forName("org.conscrypt.Conscrypt").getMethod("newProvider", null).invoke(null, null);
                    } catch (ClassNotFoundException | IllegalAccessException | IllegalArgumentException | NoSuchMethodException | InvocationTargetException unused3) {
                    }
                    if (provider2 != null) {
                        try {
                            secureRandom = SecureRandom.getInstance("SHA1PRNG", provider2);
                        } catch (GeneralSecurityException unused4) {
                        }
                    } else {
                        secureRandom = new SecureRandom();
                    }
                }
                secureRandom.nextLong();
                return secureRandom;
            case 13:
                try {
                    return (Cipher) C2433oA.b.a.zza("AES/CTR/NoPadding");
                } catch (GeneralSecurityException e3) {
                    throw new IllegalStateException(e3);
                }
            case 14:
                try {
                    return (Cipher) C2433oA.b.a.zza("AES/ECB/NOPADDING");
                } catch (GeneralSecurityException e4) {
                    throw new IllegalStateException(e4);
                }
            case 15:
                try {
                    return (Cipher) C2433oA.b.a.zza("AES/CTR/NOPADDING");
                } catch (GeneralSecurityException e5) {
                    throw new IllegalStateException(e5);
                }
            case 16:
                try {
                    return (Cipher) C2433oA.b.a.zza("AES/ECB/NoPadding");
                } catch (GeneralSecurityException e6) {
                    throw new IllegalStateException(e6);
                }
            case 17:
                return new ConcurrentLinkedQueue();
            case 18:
                return Boolean.FALSE;
            case 19:
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);
                simpleDateFormat.setLenient(false);
                simpleDateFormat.setTimeZone(okhttp3.internal.b.e);
                return simpleDateFormat;
            default:
                return new Stack();
        }
    }
}
