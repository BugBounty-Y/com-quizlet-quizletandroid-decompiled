package androidx.work.impl.background.greedy;

import android.content.ContentValues;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;
import androidx.browser.customtabs.k;
import androidx.camera.camera2.internal.compat.h;
import androidx.work.impl.j;
import com.bumptech.glide.load.e;
import com.facebook.z;
import com.google.android.gms.measurement.internal.O;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.r1;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.O1;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteStudyModeConfig;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d implements com.bumptech.glide.load.engine.cache.a {
    public long a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;

    public /* synthetic */ d(r1 r1Var) {
        this.e = r1Var;
    }

    public void a(j token) {
        Runnable runnable;
        Intrinsics.checkNotNullParameter(token, "token");
        synchronized (this.d) {
            runnable = (Runnable) ((LinkedHashMap) this.e).remove(token);
        }
        if (runnable != null) {
            ((h) this.b).a.removeCallbacks(runnable);
        }
    }

    public boolean b() {
        SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) this.c;
        if (sQLiteDatabase != null) {
            if (sQLiteDatabase != null ? sQLiteDatabase.isOpen() : false) {
                return true;
            }
        }
        return false;
    }

    @Override // com.bumptech.glide.load.engine.cache.a
    public File c(e eVar) {
        String strL = ((com.quizlet.data.repository.qclass.c) this.b).l(eVar);
        if (Log.isLoggable("DiskLruCacheWrapper", 2)) {
            Objects.toString(eVar);
        }
        try {
            com.quizlet.data.repository.school.membership.a aVarL = e().l(strL);
            if (aVarL != null) {
                return ((File[]) aVarL.b)[0];
            }
            return null;
        } catch (IOException e) {
            if (!Log.isLoggable("DiskLruCacheWrapper", 5)) {
                return null;
            }
            Log.w("DiskLruCacheWrapper", "Unable to get from disk cache", e);
            return null;
        }
    }

    @Override // com.bumptech.glide.load.engine.cache.a
    public void d(e eVar, com.quizlet.data.repository.login.a aVar) {
        com.bumptech.glide.load.engine.cache.b bVar;
        com.bumptech.glide.disklrucache.c cVarE;
        boolean z;
        String strL = ((com.quizlet.data.repository.qclass.c) this.b).l(eVar);
        com.quizlet.data.repository.explanations.myexplanations.a aVar2 = (com.quizlet.data.repository.explanations.myexplanations.a) this.d;
        synchronized (aVar2) {
            bVar = (com.bumptech.glide.load.engine.cache.b) ((HashMap) aVar2.b).get(strL);
            if (bVar == null) {
                com.airbnb.lottie.network.d dVar = (com.airbnb.lottie.network.d) aVar2.c;
                synchronized (((ArrayDeque) dVar.b)) {
                    bVar = (com.bumptech.glide.load.engine.cache.b) ((ArrayDeque) dVar.b).poll();
                }
                if (bVar == null) {
                    bVar = new com.bumptech.glide.load.engine.cache.b();
                }
                ((HashMap) aVar2.b).put(strL, bVar);
            }
            bVar.b++;
        }
        bVar.a.lock();
        try {
            if (Log.isLoggable("DiskLruCacheWrapper", 2)) {
                Objects.toString(eVar);
            }
            try {
                cVarE = e();
            } catch (IOException e) {
                if (Log.isLoggable("DiskLruCacheWrapper", 5)) {
                    Log.w("DiskLruCacheWrapper", "Unable to put to disk cache", e);
                }
            }
            if (cVarE.l(strL) != null) {
                return;
            }
            k kVarI = cVarE.i(strL);
            if (kVarI == null) {
                throw new IllegalStateException("Had two simultaneous puts for: ".concat(strL));
            }
            try {
                if (((com.bumptech.glide.load.b) aVar.a).m(aVar.b, kVarI.g(), (com.bumptech.glide.load.h) aVar.c)) {
                    com.bumptech.glide.disklrucache.c.a((com.bumptech.glide.disklrucache.c) kVarI.d, kVarI, true);
                    kVarI.a = true;
                }
                if (!z) {
                    try {
                        kVarI.b();
                    } catch (IOException unused) {
                    }
                }
            } finally {
                if (!kVarI.a) {
                    try {
                        kVarI.b();
                    } catch (IOException unused2) {
                    }
                }
            }
        } finally {
            ((com.quizlet.data.repository.explanations.myexplanations.a) this.d).j(strL);
        }
    }

    public synchronized com.bumptech.glide.disklrucache.c e() {
        try {
            if (((com.bumptech.glide.disklrucache.c) this.e) == null) {
                this.e = com.bumptech.glide.disklrucache.c.q((File) this.c, this.a);
            }
        } catch (Throwable th) {
            throw th;
        }
        return (com.bumptech.glide.disklrucache.c) this.e;
    }

    public WriteStudyModeConfig f() {
        com.quizlet.billing.register.a aVar = (com.quizlet.billing.register.a) this.c;
        long j = this.a;
        G1 g1 = (G1) this.b;
        String strC = com.quizlet.billing.register.a.c(j, g1, "learnTermFirst");
        SharedPreferences sharedPreferences = aVar.a;
        return new WriteStudyModeConfig(sharedPreferences.getBoolean(strC, false) ? O1.WORD : O1.DEFINITION, sharedPreferences.getBoolean(com.quizlet.billing.register.a.c(j, g1, "learnTypeAnswersBoolean"), true), ((SharedPreferences) this.e).getBoolean("speakText", true), sharedPreferences.getBoolean(com.quizlet.billing.register.a.c(j, g1, "learnShowImage"), true), ((z) this.d).a(j, G1.SET));
    }

    public void g(com.snowplowanalytics.snowplow.payload.b payload) throws IOException {
        SQLiteDatabase sQLiteDatabase;
        byte[] byteArray;
        Intrinsics.checkNotNullParameter(payload, "payload");
        if (!b() || (sQLiteDatabase = (SQLiteDatabase) this.c) == null) {
            return;
        }
        HashMap map = payload.b;
        Intrinsics.checkNotNullParameter(map, "map");
        HashMap map2 = new HashMap();
        for (Map.Entry entry : map.entrySet()) {
            map2.put((String) entry.getKey(), entry.getValue().toString());
        }
        Intrinsics.checkNotNullParameter(map2, "map");
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(map2);
            objectOutputStream.close();
            byteArrayOutputStream.close();
            byteArray = byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            byteArray = null;
        }
        ContentValues contentValues = new ContentValues(2);
        contentValues.put("eventData", byteArray);
        this.a = sQLiteDatabase.insert("events", null, contentValues);
        Intrinsics.checkNotNullExpressionValue("d", "TAG");
        com.snowplowanalytics.core.tracker.e.a("d", "Added event to database: %s", Long.valueOf(this.a));
    }

    public void h() {
        if (!b() || ((ArrayList) this.b).size() <= 0) {
            return;
        }
        synchronized (this) {
            try {
                Iterator it2 = ((ArrayList) this.b).iterator();
                while (it2.hasNext()) {
                    g((com.snowplowanalytics.snowplow.payload.b) it2.next());
                }
                ((ArrayList) this.b).clear();
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void i(WriteStudyModeConfig writeStudyModeConfig) {
        boolean zEquals = O1.WORD.equals(writeStudyModeConfig.a);
        SharedPreferences sharedPreferences = ((com.quizlet.billing.register.a) this.c).a;
        SharedPreferences.Editor editorEdit = sharedPreferences.edit();
        long j = this.a;
        G1 g1 = (G1) this.b;
        editorEdit.putBoolean(com.quizlet.billing.register.a.c(j, g1, "learnTermFirst"), zEquals).apply();
        sharedPreferences.edit().putBoolean(com.quizlet.billing.register.a.c(j, g1, "learnTypeAnswersBoolean"), writeStudyModeConfig.b).apply();
        ((SharedPreferences) this.e).edit().putBoolean("speakText", writeStudyModeConfig.c).apply();
        sharedPreferences.edit().putBoolean(com.quizlet.billing.register.a.c(j, g1, "learnShowImage"), writeStudyModeConfig.d).apply();
        ((z) this.d).c(j, g1, writeStudyModeConfig.e);
    }

    public void j(j token) {
        Intrinsics.checkNotNullParameter(token, "token");
        androidx.credentials.playservices.controllers.c cVar = new androidx.credentials.playservices.controllers.c(7, this, token);
        synchronized (this.d) {
        }
        h hVar = (h) this.b;
        hVar.a.postDelayed(cVar, this.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x009a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean k(long r11, com.google.android.gms.internal.measurement.U0 r13) {
        /*
            r10 = this;
            java.lang.Object r0 = r10.d
            java.util.ArrayList r0 = (java.util.ArrayList) r0
            if (r0 != 0) goto Ld
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            r10.d = r0
        Ld:
            java.lang.Object r0 = r10.c
            java.util.ArrayList r0 = (java.util.ArrayList) r0
            if (r0 != 0) goto L1a
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>()
            r10.c = r0
        L1a:
            java.lang.Object r0 = r10.d
            java.util.ArrayList r0 = (java.util.ArrayList) r0
            boolean r0 = r0.isEmpty()
            r1 = 0
            if (r0 != 0) goto L45
            java.lang.Object r0 = r10.d
            java.util.ArrayList r0 = (java.util.ArrayList) r0
            java.lang.Object r0 = r0.get(r1)
            com.google.android.gms.internal.measurement.U0 r0 = (com.google.android.gms.internal.measurement.U0) r0
            long r2 = r0.q()
            r4 = 1000(0x3e8, double:4.94E-321)
            long r2 = r2 / r4
            r6 = 60
            long r2 = r2 / r6
            long r2 = r2 / r6
            long r8 = r13.q()
            long r8 = r8 / r4
            long r8 = r8 / r6
            long r8 = r8 / r6
            int r0 = (r2 > r8 ? 1 : (r2 == r8 ? 0 : -1))
            if (r0 != 0) goto Lcc
        L45:
            long r2 = r10.a
            int r0 = r13.d()
            long r4 = (long) r0
            long r2 = r2 + r4
            java.lang.Object r0 = r10.e
            com.google.android.gms.measurement.internal.r1 r0 = (com.google.android.gms.measurement.internal.r1) r0
            com.google.android.gms.measurement.internal.e r4 = r0.h0()
            com.google.android.gms.measurement.internal.s r5 = com.google.android.gms.measurement.internal.AbstractC3893t.q1
            r6 = 0
            boolean r4 = r4.f0(r6, r5)
            if (r4 == 0) goto L81
            java.lang.Object r4 = r10.d
            java.util.ArrayList r4 = (java.util.ArrayList) r4
            boolean r4 = r4.isEmpty()
            if (r4 != 0) goto L9a
            r0.h0()
            com.google.android.gms.measurement.internal.s r4 = com.google.android.gms.measurement.internal.AbstractC3893t.j
            java.lang.Object r4 = r4.a(r6)
            java.lang.Integer r4 = (java.lang.Integer) r4
            int r4 = r4.intValue()
            int r4 = java.lang.Math.max(r1, r4)
            long r4 = (long) r4
            int r4 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r4 >= 0) goto Lcc
            goto L9a
        L81:
            r0.h0()
            com.google.android.gms.measurement.internal.s r4 = com.google.android.gms.measurement.internal.AbstractC3893t.j
            java.lang.Object r4 = r4.a(r6)
            java.lang.Integer r4 = (java.lang.Integer) r4
            int r4 = r4.intValue()
            int r4 = java.lang.Math.max(r1, r4)
            long r4 = (long) r4
            int r4 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r4 < 0) goto L9a
            goto Lcc
        L9a:
            r10.a = r2
            java.lang.Object r2 = r10.d
            java.util.ArrayList r2 = (java.util.ArrayList) r2
            r2.add(r13)
            java.lang.Object r13 = r10.c
            java.util.ArrayList r13 = (java.util.ArrayList) r13
            java.lang.Long r11 = java.lang.Long.valueOf(r11)
            r13.add(r11)
            java.lang.Object r11 = r10.d
            java.util.ArrayList r11 = (java.util.ArrayList) r11
            int r11 = r11.size()
            r0.h0()
            com.google.android.gms.measurement.internal.s r12 = com.google.android.gms.measurement.internal.AbstractC3893t.k
            java.lang.Object r12 = r12.a(r6)
            java.lang.Integer r12 = (java.lang.Integer) r12
            int r12 = r12.intValue()
            r13 = 1
            int r12 = java.lang.Math.max(r13, r12)
            if (r11 < r12) goto Lcd
        Lcc:
            return r1
        Lcd:
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.background.greedy.d.k(long, com.google.android.gms.internal.measurement.U0):boolean");
    }

    public void l() {
        O o = (O) this.e;
        o.S();
        ((Y) o.b).n.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        SharedPreferences.Editor editorEdit = o.X().edit();
        editorEdit.remove((String) this.c);
        editorEdit.remove((String) this.d);
        editorEdit.putLong((String) this.b, jCurrentTimeMillis);
        editorEdit.apply();
    }
}
