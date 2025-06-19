package androidx.camera.camera2.internal;

import android.os.SystemClock;
import com.google.android.gms.internal.ads.C2608sE;
import com.google.android.gms.internal.ads.InterfaceC2512q3;
import com.pubmatic.sdk.video.c;
import com.quizlet.data.model.C4116c1;
import com.quizlet.data.model.C4127f1;
import com.quizlet.data.model.I0;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.camera.camera2.internal.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0148z implements InterfaceC2512q3, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public long b;
    public long c;
    public Object d;

    public C0148z() {
        this.a = 4;
        this.b = -9223372036854775807L;
        this.c = -9223372036854775807L;
    }

    public synchronized Object a(Object obj) {
        com.bumptech.glide.util.i iVar;
        iVar = (com.bumptech.glide.util.i) ((LinkedHashMap) this.d).get(obj);
        return iVar != null ? iVar.a : null;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 6:
                I0 it2 = (I0) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                boolean zB = Intrinsics.b(it2, com.quizlet.data.model.Q.a);
                com.quizlet.data.interactor.progress.e eVar = (com.quizlet.data.interactor.progress.e) this.d;
                if (!zB) {
                    if (it2 instanceof C4116c1) {
                        return eVar.a.d((C4127f1) ((C4116c1) it2).a);
                    }
                    throw new NoWhenBranchMatchedException();
                }
                eVar.getClass();
                return new io.reactivex.rxjava3.internal.operators.completable.c(new NoSuchElementException("Local ProgressReset does not exist with userId=" + this.b + "&setId=" + this.c), 3);
            default:
                I0 remoteData = (I0) obj;
                Intrinsics.checkNotNullParameter(remoteData, "remoteData");
                if (!(remoteData instanceof C4116c1)) {
                    if (remoteData instanceof com.quizlet.data.model.Q) {
                        return io.reactivex.rxjava3.internal.operators.observable.E.a;
                    }
                    throw new NoWhenBranchMatchedException();
                }
                com.quizlet.data.repository.progress.b bVar = (com.quizlet.data.repository.progress.b) this.d;
                return new io.reactivex.rxjava3.internal.operators.observable.J(new io.reactivex.rxjava3.internal.operators.mixed.b(0, ((com.quizlet.data.repository.folderwithcreator.e) bVar.b).r((C4127f1) ((C4116c1) remoteData).a), ((com.quizlet.data.repository.folderwithcreator.e) bVar.b).i(this.b, this.c)), new androidx.compose.foundation.text.input.internal.u(bVar, false, remoteData, 17), 5);
        }
    }

    public int b() {
        if (!((B) this.d).c()) {
            return 700;
        }
        long jUptimeMillis = SystemClock.uptimeMillis();
        if (this.c == -1) {
            this.c = jUptimeMillis;
        }
        long j = jUptimeMillis - this.c;
        if (j <= 120000) {
            return 1000;
        }
        return j <= 300000 ? 2000 : 4000;
    }

    public int c() {
        boolean zC = ((B) this.d).c();
        long j = this.b;
        if (!zC) {
            return j > 0 ? Math.min((int) j, c.a.DEFAULT_MEDIA_URI_TIMEOUT) : c.a.DEFAULT_MEDIA_URI_TIMEOUT;
        }
        if (j > 0) {
            return Math.min((int) j, 1800000);
        }
        return 1800000;
    }

    public int d(Object obj) {
        return 1;
    }

    public void e(Object obj, Object obj2) {
    }

    public synchronized Object f(Object obj, Object obj2) {
        int iD = d(obj2);
        long j = iD;
        if (j >= this.b) {
            e(obj, obj2);
            return null;
        }
        if (obj2 != null) {
            this.c += j;
        }
        com.bumptech.glide.util.i iVar = (com.bumptech.glide.util.i) ((LinkedHashMap) this.d).put(obj, obj2 == null ? null : new com.bumptech.glide.util.i(obj2, iD));
        if (iVar != null) {
            this.c -= iVar.b;
            if (!iVar.a.equals(obj2)) {
                e(obj, iVar.a);
            }
        }
        g(this.b);
        return iVar != null ? iVar.a : null;
    }

    public synchronized void g(long j) {
        while (this.c > j) {
            Iterator it2 = ((LinkedHashMap) this.d).entrySet().iterator();
            Map.Entry entry = (Map.Entry) it2.next();
            com.bumptech.glide.util.i iVar = (com.bumptech.glide.util.i) entry.getValue();
            this.c -= iVar.b;
            Object key = entry.getKey();
            it2.remove();
            e(key, iVar.a);
        }
    }

    public void h(Exception exc) {
        boolean z;
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        if (((Exception) this.d) == null) {
            this.d = exc;
        }
        if (this.b == -9223372036854775807L) {
            synchronized (C2608sE.Z) {
                z = C2608sE.b0 > 0;
            }
            if (!z) {
                this.b = 200 + jElapsedRealtime;
            }
        }
        long j = this.b;
        if (j == -9223372036854775807L || jElapsedRealtime < j) {
            this.c = jElapsedRealtime + 50;
            return;
        }
        Exception exc2 = (Exception) this.d;
        if (exc2 != exc) {
            exc2.addSuppressed(exc);
        }
        Exception exc3 = (Exception) this.d;
        this.d = null;
        this.b = -9223372036854775807L;
        this.c = -9223372036854775807L;
        throw exc3;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2512q3
    public void i(MessageDigest[] messageDigestArr, long j, int i) throws IOException {
        MappedByteBuffer map = ((FileChannel) this.d).map(FileChannel.MapMode.READ_ONLY, this.b + j, i);
        map.load();
        for (MessageDigest messageDigest : messageDigestArr) {
            map.position(0);
            messageDigest.update(map);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2512q3
    public long zza() {
        return this.c;
    }

    public /* synthetic */ C0148z(Object obj, long j, long j2, int i) {
        this.a = i;
        this.d = obj;
        this.b = j;
        this.c = j2;
    }

    public C0148z(int i, long j) {
        this.a = i;
        switch (i) {
            case 2:
                this.c = Long.MIN_VALUE;
                this.d = new Object();
                this.b = j;
                break;
            default:
                this.d = new LinkedHashMap(100, 0.75f, true);
                this.b = j;
                break;
        }
    }

    public C0148z(long j, long j2, TimeUnit timeUnit) {
        this.a = 5;
        this.b = j;
        this.c = j2;
        this.d = timeUnit;
    }

    public C0148z(B b, long j) {
        this.a = 0;
        this.d = b;
        this.c = -1L;
        this.b = j;
    }
}
