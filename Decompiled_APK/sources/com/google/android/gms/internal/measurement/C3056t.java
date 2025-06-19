package com.google.android.gms.internal.measurement;

import android.content.ContentProviderClient;
import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.RemoteException;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3554w3;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.measurement.t, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3056t {
    public final Object a;
    public final Object b;

    public /* synthetic */ C3056t(C3083y1 c3083y1, String str) {
        this.a = c3083y1;
        this.b = str;
    }

    public InterfaceC3027n a(C1721Kc c1721Kc, InterfaceC3027n interfaceC3027n) {
        AbstractC3554w3.c(c1721Kc);
        if (!(interfaceC3027n instanceof C3032o)) {
            return interfaceC3027n;
        }
        C3032o c3032o = (C3032o) interfaceC3027n;
        ArrayList arrayList = c3032o.b;
        HashMap map = (HashMap) this.a;
        String str = c3032o.a;
        return (map.containsKey(str) ? (C3051s) map.get(str) : (C3051s) this.b).a(str, c1721Kc, arrayList);
    }

    public Object b() {
        Uri uri;
        ContentProviderClient contentProviderClientAcquireUnstableContentProviderClient;
        String string;
        C3083y1 c3083y1 = (C3083y1) this.a;
        String str = (String) this.b;
        Context context = (Context) c3083y1.c;
        context.getClass();
        ContentResolver contentResolver = context.getContentResolver();
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = AbstractC3044q1.a;
        if (contentResolver == null) {
            dVar.getClass();
            throw new IllegalStateException("ContentResolver needed with GservicesDelegateSupplier.init()");
        }
        synchronized (dVar) {
            try {
                if (((HashMap) dVar.b) == null) {
                    ((AtomicBoolean) dVar.a).set(false);
                    dVar.b = new HashMap(16, 1.0f);
                    dVar.g = new Object();
                    contentResolver.registerContentObserver(AbstractC3048r1.a, true, new androidx.compose.ui.platform.o1(dVar, 2));
                } else if (((AtomicBoolean) dVar.a).getAndSet(false)) {
                    ((HashMap) dVar.b).clear();
                    ((HashMap) dVar.c).clear();
                    ((HashMap) dVar.d).clear();
                    ((HashMap) dVar.e).clear();
                    ((HashMap) dVar.f).clear();
                    dVar.g = new Object();
                }
                Object obj = dVar.g;
                String str2 = null;
                if (((HashMap) dVar.b).containsKey(str)) {
                    String str3 = (String) ((HashMap) dVar.b).get(str);
                    if (str3 != null) {
                        str2 = str3;
                    }
                    return str2;
                }
                try {
                    uri = AbstractC3048r1.a;
                    contentProviderClientAcquireUnstableContentProviderClient = contentResolver.acquireUnstableContentProviderClient(uri);
                    try {
                    } finally {
                        contentProviderClientAcquireUnstableContentProviderClient.release();
                    }
                } catch (zzjg unused) {
                }
                if (contentProviderClientAcquireUnstableContentProviderClient == null) {
                    throw new zzjg("Unable to acquire ContentProviderClient");
                }
                try {
                    Cursor cursorQuery = contentProviderClientAcquireUnstableContentProviderClient.query(uri, null, null, new String[]{str}, null);
                    try {
                        if (cursorQuery == null) {
                            throw new zzjg("ContentProvider query returned null cursor");
                        }
                        if (cursorQuery.moveToFirst()) {
                            string = cursorQuery.getString(1);
                            cursorQuery.close();
                        } else {
                            cursorQuery.close();
                            string = null;
                        }
                        if (string != null && string.equals(null)) {
                            string = null;
                        }
                        synchronized (dVar) {
                            try {
                                if (obj == dVar.g) {
                                    ((HashMap) dVar.b).put(str, string);
                                }
                            } finally {
                            }
                        }
                        if (string != null) {
                            return string;
                        }
                        return null;
                    } finally {
                    }
                } catch (RemoteException e) {
                    throw new zzjg("ContentProvider query failed", e);
                }
            } finally {
            }
        }
    }

    public void c(C1721Kc c1721Kc, com.quizlet.data.repository.user.a aVar) {
        N1 n1 = new N1(aVar);
        TreeMap treeMap = (TreeMap) this.a;
        for (Integer num : treeMap.keySet()) {
            C2967b c2967bA = ((C2967b) aVar.c).clone();
            InterfaceC3027n interfaceC3027nD = ((C3022m) treeMap.get(num)).d(c1721Kc, Collections.singletonList(n1));
            int iB = interfaceC3027nD instanceof C2992g ? AbstractC3554w3.b(((C2992g) interfaceC3027nD).a.doubleValue()) : -1;
            if (iB == 2 || iB == -1) {
                aVar.c = c2967bA;
            }
        }
        TreeMap treeMap2 = (TreeMap) this.b;
        Iterator it2 = treeMap2.keySet().iterator();
        while (it2.hasNext()) {
            InterfaceC3027n interfaceC3027nD2 = ((C3022m) treeMap2.get((Integer) it2.next())).d(c1721Kc, Collections.singletonList(n1));
            if (interfaceC3027nD2 instanceof C2992g) {
                AbstractC3554w3.b(((C2992g) interfaceC3027nD2).a.doubleValue());
            }
        }
    }

    public void d(C3051s c3051s) {
        Iterator it2 = c3051s.a.iterator();
        while (it2.hasNext()) {
            ((HashMap) this.a).put(Integer.valueOf(((EnumC3071w) it2.next()).a).toString(), c3051s);
        }
    }

    public C3056t(int i) {
        switch (i) {
            case 2:
                this.a = new TreeMap();
                this.b = new TreeMap();
                break;
            default:
                this.a = new HashMap();
                this.b = new C3051s(6);
                C3051s c3051s = new C3051s(0);
                ArrayList arrayList = c3051s.a;
                arrayList.add(EnumC3071w.BITWISE_AND);
                arrayList.add(EnumC3071w.BITWISE_LEFT_SHIFT);
                arrayList.add(EnumC3071w.BITWISE_NOT);
                arrayList.add(EnumC3071w.BITWISE_OR);
                arrayList.add(EnumC3071w.BITWISE_RIGHT_SHIFT);
                arrayList.add(EnumC3071w.BITWISE_UNSIGNED_RIGHT_SHIFT);
                arrayList.add(EnumC3071w.BITWISE_XOR);
                d(c3051s);
                C3051s c3051s2 = new C3051s(1);
                ArrayList arrayList2 = c3051s2.a;
                arrayList2.add(EnumC3071w.EQUALS);
                arrayList2.add(EnumC3071w.GREATER_THAN);
                arrayList2.add(EnumC3071w.GREATER_THAN_EQUALS);
                arrayList2.add(EnumC3071w.IDENTITY_EQUALS);
                arrayList2.add(EnumC3071w.IDENTITY_NOT_EQUALS);
                arrayList2.add(EnumC3071w.LESS_THAN);
                arrayList2.add(EnumC3071w.LESS_THAN_EQUALS);
                arrayList2.add(EnumC3071w.NOT_EQUALS);
                d(c3051s2);
                C3051s c3051s3 = new C3051s(2);
                ArrayList arrayList3 = c3051s3.a;
                arrayList3.add(EnumC3071w.APPLY);
                arrayList3.add(EnumC3071w.BLOCK);
                arrayList3.add(EnumC3071w.BREAK);
                arrayList3.add(EnumC3071w.CASE);
                arrayList3.add(EnumC3071w.DEFAULT);
                arrayList3.add(EnumC3071w.CONTINUE);
                arrayList3.add(EnumC3071w.DEFINE_FUNCTION);
                arrayList3.add(EnumC3071w.FN);
                arrayList3.add(EnumC3071w.IF);
                arrayList3.add(EnumC3071w.QUOTE);
                arrayList3.add(EnumC3071w.RETURN);
                arrayList3.add(EnumC3071w.SWITCH);
                arrayList3.add(EnumC3071w.TERNARY);
                d(c3051s3);
                C3051s c3051s4 = new C3051s(3);
                ArrayList arrayList4 = c3051s4.a;
                arrayList4.add(EnumC3071w.AND);
                arrayList4.add(EnumC3071w.NOT);
                arrayList4.add(EnumC3071w.OR);
                d(c3051s4);
                C3051s c3051s5 = new C3051s(4);
                ArrayList arrayList5 = c3051s5.a;
                arrayList5.add(EnumC3071w.FOR_IN);
                arrayList5.add(EnumC3071w.FOR_IN_CONST);
                arrayList5.add(EnumC3071w.FOR_IN_LET);
                arrayList5.add(EnumC3071w.FOR_LET);
                arrayList5.add(EnumC3071w.FOR_OF);
                arrayList5.add(EnumC3071w.FOR_OF_CONST);
                arrayList5.add(EnumC3071w.FOR_OF_LET);
                arrayList5.add(EnumC3071w.WHILE);
                d(c3051s5);
                C3051s c3051s6 = new C3051s(5);
                ArrayList arrayList6 = c3051s6.a;
                arrayList6.add(EnumC3071w.ADD);
                arrayList6.add(EnumC3071w.DIVIDE);
                arrayList6.add(EnumC3071w.MODULUS);
                arrayList6.add(EnumC3071w.MULTIPLY);
                arrayList6.add(EnumC3071w.NEGATE);
                arrayList6.add(EnumC3071w.POST_DECREMENT);
                arrayList6.add(EnumC3071w.POST_INCREMENT);
                arrayList6.add(EnumC3071w.PRE_DECREMENT);
                arrayList6.add(EnumC3071w.PRE_INCREMENT);
                arrayList6.add(EnumC3071w.SUBTRACT);
                d(c3051s6);
                C3051s c3051s7 = new C3051s(7);
                ArrayList arrayList7 = c3051s7.a;
                arrayList7.add(EnumC3071w.ASSIGN);
                arrayList7.add(EnumC3071w.CONST);
                arrayList7.add(EnumC3071w.CREATE_ARRAY);
                arrayList7.add(EnumC3071w.CREATE_OBJECT);
                arrayList7.add(EnumC3071w.EXPRESSION_LIST);
                arrayList7.add(EnumC3071w.GET);
                arrayList7.add(EnumC3071w.GET_INDEX);
                arrayList7.add(EnumC3071w.GET_PROPERTY);
                arrayList7.add(EnumC3071w.NULL);
                arrayList7.add(EnumC3071w.SET_PROPERTY);
                arrayList7.add(EnumC3071w.TYPEOF);
                arrayList7.add(EnumC3071w.UNDEFINED);
                arrayList7.add(EnumC3071w.VAR);
                d(c3051s7);
                break;
        }
    }
}
