package com.quizlet.data.repository.explanations.textbook;

import android.graphics.Typeface;
import android.os.Message;
import androidx.core.os.d;
import androidx.emoji2.text.flatbuffer.b;
import androidx.emoji2.text.v;
import androidx.emoji2.text.y;
import androidx.recyclerview.widget.C1372j;
import com.google.android.gms.internal.ads.B3;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2726v3;
import com.google.android.gms.internal.ads.El;
import com.google.android.gms.internal.ads.H3;
import com.google.android.gms.internal.ads.InterfaceC2907zC;
import com.google.android.gms.internal.ads.Lw;
import com.google.android.gms.internal.ads.Mw;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.firebase.sessions.b0;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.PriorityBlockingQueue;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import okhttp3.A;
import okhttp3.s;
import retrofit2.AbstractC5185j;
import retrofit2.C5176a;
import retrofit2.C5177b;
import retrofit2.F;
import retrofit2.L;

/* loaded from: classes2.dex */
public final class a {
    public Object a;
    public Object b;
    public Object c;
    public Object d;

    public a(int i) {
        switch (i) {
            case 8:
                this.c = new ArrayList();
                this.d = new ArrayList();
                break;
            default:
                this.a = null;
                this.b = null;
                this.c = null;
                this.d = Lw.e;
                break;
        }
    }

    public static final Message a(a aVar, ArrayList arrayList, int i) {
        Object obj;
        aVar.getClass();
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((Message) next).what == i) {
                arrayList2.add(next);
            }
        }
        Iterator it3 = arrayList2.iterator();
        if (it3.hasNext()) {
            Object next2 = it3.next();
            if (it3.hasNext()) {
                long when = ((Message) next2).getWhen();
                do {
                    Object next3 = it3.next();
                    long when2 = ((Message) next3).getWhen();
                    if (when < when2) {
                        next2 = next3;
                        when = when2;
                    }
                } while (it3.hasNext());
            }
            obj = next2;
        } else {
            obj = null;
        }
        return (Message) obj;
    }

    public void b(AbstractC5185j abstractC5185j) {
        ArrayList arrayList = (ArrayList) this.c;
        Objects.requireNonNull(abstractC5185j, "factory == null");
        arrayList.add(abstractC5185j);
    }

    public void c(String str) {
        Objects.requireNonNull(str, "baseUrl == null");
        Intrinsics.checkNotNullParameter(str, "<this>");
        C1372j c1372j = new C1372j();
        c1372j.l(null, str);
        d(c1372j.d());
    }

    public void d(s sVar) {
        Objects.requireNonNull(sVar, "baseUrl == null");
        if ("".equals(sVar.f.get(r0.size() - 1))) {
            this.b = sVar;
        } else {
            throw new IllegalArgumentException("baseUrl must end in /: " + sVar);
        }
    }

    public L e() {
        if (((s) this.b) == null) {
            throw new IllegalStateException("Base URL required.");
        }
        A a = (A) this.a;
        if (a == null) {
            a = new A();
        }
        A a2 = a;
        d dVar = F.a;
        C5176a c5176a = F.c;
        ArrayList arrayList = new ArrayList((ArrayList) this.d);
        List listA = c5176a.a(dVar);
        arrayList.addAll(listA);
        List listB = c5176a.b();
        int size = listB.size();
        ArrayList arrayList2 = (ArrayList) this.c;
        ArrayList arrayList3 = new ArrayList(arrayList2.size() + 1 + size);
        arrayList3.add(new C5177b(0));
        arrayList3.addAll(arrayList2);
        arrayList3.addAll(listB);
        s sVar = (s) this.b;
        List listUnmodifiableList = Collections.unmodifiableList(arrayList3);
        List listUnmodifiableList2 = Collections.unmodifiableList(arrayList);
        listA.size();
        return new L(a2, sVar, listUnmodifiableList, listUnmodifiableList2, dVar);
    }

    public void f(int i) {
        ArrayList arrayList = new ArrayList();
        ((LinkedBlockingDeque) this.c).drainTo(arrayList);
        Message messageObtain = Message.obtain(null, i, 0, 0);
        Intrinsics.checkNotNullExpressionValue(messageObtain, "obtain(null, messageCode, 0, 0)");
        arrayList.add(messageObtain);
        E.A(E.c((CoroutineContext) this.a), null, null, new b0(this, arrayList, null), 3);
    }

    public void g(int i) throws GeneralSecurityException {
        if (i != 12 && i != 16) {
            throw new GeneralSecurityException(String.format("Invalid IV size in bytes %d; acceptable values have 12 or 16 bytes", Integer.valueOf(i)));
        }
        this.b = Integer.valueOf(i);
    }

    public synchronized void h(B3 b3) {
        try {
            HashMap map = (HashMap) this.a;
            String strB = b3.b();
            List list = (List) map.remove(strB);
            if (list == null || list.isEmpty()) {
                return;
            }
            if (H3.a) {
                H3.b("%d waiting requests for cacheKey=%s; resend to network", Integer.valueOf(list.size()), strB);
            }
            B3 b32 = (B3) list.remove(0);
            map.put(strB, list);
            synchronized (b32.e) {
                b32.k = this;
            }
            try {
                ((PriorityBlockingQueue) this.c).put(b32);
            } catch (InterruptedException e) {
                H3.a("Couldn't add request to queue. %s", e.toString());
                Thread.currentThread().interrupt();
                C2726v3 c2726v3 = (C2726v3) this.b;
                c2726v3.d = true;
                c2726v3.interrupt();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public void i(int i) throws InvalidAlgorithmParameterException {
        if (i != 16 && i != 24 && i != 32) {
            throw new InvalidAlgorithmParameterException(String.format("Invalid key size %d; only 16-byte, 24-byte and 32-byte AES keys are supported", Integer.valueOf(i)));
        }
        this.a = Integer.valueOf(i);
    }

    public void j() {
        this.c = 16;
    }

    public synchronized boolean k(B3 b3) {
        try {
            HashMap map = (HashMap) this.a;
            String strB = b3.b();
            if (!map.containsKey(strB)) {
                map.put(strB, null);
                synchronized (b3.e) {
                    b3.k = this;
                }
                if (H3.a) {
                    H3.c("new request, sending to network %s", strB);
                }
                return false;
            }
            List arrayList = (List) map.get(strB);
            if (arrayList == null) {
                arrayList = new ArrayList();
            }
            b3.d("waiting-for-response");
            arrayList.add(b3);
            map.put(strB, arrayList);
            if (H3.a) {
                H3.c("Request for cacheKey=%s is in flight, putting on hold.", strB);
            }
            return true;
        } catch (Throwable th) {
            throw th;
        }
    }

    public Mw l() throws GeneralSecurityException {
        Integer num = (Integer) this.a;
        if (num == null) {
            throw new GeneralSecurityException("Key size is not set");
        }
        if (((Integer) this.b) == null) {
            throw new GeneralSecurityException("IV size is not set");
        }
        if (((Integer) this.c) == null) {
            throw new GeneralSecurityException("Tag size is not set");
        }
        int iIntValue = num.intValue();
        int iIntValue2 = ((Integer) this.b).intValue();
        ((Integer) this.c).getClass();
        return new Mw(iIntValue, iIntValue2, (Lw) this.d);
    }

    public a(C2227jd c2227jd, C2227jd c2227jd2, El el, InterfaceC2907zC interfaceC2907zC) {
        this.a = c2227jd;
        this.b = c2227jd2;
        this.c = el;
        this.d = interfaceC2907zC;
    }

    public a(Typeface typeface, b bVar) {
        int i;
        int i2;
        int i3;
        int i4;
        this.d = typeface;
        this.a = bVar;
        this.c = new v(1024);
        int iA = bVar.a(6);
        if (iA != 0) {
            int i5 = iA + bVar.a;
            i = ((ByteBuffer) bVar.d).getInt(((ByteBuffer) bVar.d).getInt(i5) + i5);
        } else {
            i = 0;
        }
        this.b = new char[i * 2];
        int iA2 = bVar.a(6);
        if (iA2 != 0) {
            int i6 = iA2 + bVar.a;
            i2 = ((ByteBuffer) bVar.d).getInt(((ByteBuffer) bVar.d).getInt(i6) + i6);
        } else {
            i2 = 0;
        }
        for (int i7 = 0; i7 < i2; i7++) {
            y yVar = new y(this, i7);
            androidx.emoji2.text.flatbuffer.a aVarB = yVar.b();
            int iA3 = aVarB.a(4);
            Character.toChars(iA3 != 0 ? ((ByteBuffer) aVarB.d).getInt(iA3 + aVarB.a) : 0, (char[]) this.b, i7 * 2);
            androidx.emoji2.text.flatbuffer.a aVarB2 = yVar.b();
            int iA4 = aVarB2.a(16);
            if (iA4 != 0) {
                int i8 = iA4 + aVarB2.a;
                i3 = ((ByteBuffer) aVarB2.d).getInt(((ByteBuffer) aVarB2.d).getInt(i8) + i8);
            } else {
                i3 = 0;
            }
            AbstractC3242q6.c("invalid metadata codepoint length", i3 > 0);
            androidx.emoji2.text.flatbuffer.a aVarB3 = yVar.b();
            int iA5 = aVarB3.a(16);
            if (iA5 != 0) {
                int i9 = iA5 + aVarB3.a;
                i4 = ((ByteBuffer) aVarB3.d).getInt(((ByteBuffer) aVarB3.d).getInt(i9) + i9);
            } else {
                i4 = 0;
            }
            ((v) this.c).a(yVar, 0, i4 - 1);
        }
    }
}
