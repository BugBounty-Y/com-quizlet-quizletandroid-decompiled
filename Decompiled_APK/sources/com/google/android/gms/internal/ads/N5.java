package com.google.android.gms.internal.ads;

import android.graphics.Rect;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;
import android.widget.EditText;
import android.widget.TextView;
import androidx.compose.material3.C0676l1;

/* loaded from: classes2.dex */
public final class N5 extends Thread {
    public boolean a;
    public boolean b;
    public final Object c;
    public final I3 d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;
    public final int i;
    public final int j;
    public final int k;
    public final int l;
    public final String m;
    public final boolean n;
    public final boolean o;

    public N5() {
        I3 i3 = new I3(4, (byte) 0);
        this.a = false;
        this.b = false;
        this.d = i3;
        this.c = new Object();
        this.f = ((Long) P7.d.o()).intValue();
        this.g = ((Long) P7.a.o()).intValue();
        this.h = ((Long) P7.e.o()).intValue();
        this.i = ((Long) P7.c.o()).intValue();
        C2601s7 c2601s7 = AbstractC2773w7.Z;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        this.j = ((Integer) rVar.c.a(c2601s7)).intValue();
        C2601s7 c2601s72 = AbstractC2773w7.a0;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        this.k = ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).intValue();
        this.l = ((Integer) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.b0)).intValue();
        this.e = ((Long) P7.f.o()).intValue();
        this.m = (String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.d0);
        this.n = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.e0)).booleanValue();
        this.o = ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.f0)).booleanValue();
        ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.g0)).getClass();
        setName("ContentFetchTask");
    }

    public final C0676l1 a(View view, J5 j5) {
        if (view != null) {
            boolean globalVisibleRect = view.getGlobalVisibleRect(new Rect());
            if ((view instanceof TextView) && !(view instanceof EditText)) {
                CharSequence text = ((TextView) view).getText();
                if (!TextUtils.isEmpty(text)) {
                    j5.c(text.toString(), globalVisibleRect, view.getX(), view.getY(), view.getWidth(), view.getHeight());
                    return new C0676l1(1, 0, false);
                }
            } else {
                if ((view instanceof WebView) && !(view instanceof InterfaceC2529qe)) {
                    WebView webView = (WebView) view;
                    synchronized (j5.g) {
                        j5.m++;
                    }
                    webView.post(new C(this, j5, webView, globalVisibleRect));
                    return new C0676l1(0, 1, false);
                }
                if (view instanceof ViewGroup) {
                    ViewGroup viewGroup = (ViewGroup) view;
                    int i = 0;
                    int i2 = 0;
                    for (int i3 = 0; i3 < viewGroup.getChildCount(); i3++) {
                        C0676l1 c0676l1A = a(viewGroup.getChildAt(i3), j5);
                        i += c0676l1A.a;
                        i2 += c0676l1A.b;
                    }
                    return new C0676l1(i, i2, false);
                }
            }
        }
        return new C0676l1(0, 0, false);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x004f, code lost:
    
        if (r5.importance != 100) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x0055, code lost:
    
        if (r4.inKeyguardRestrictedInputMode() != false) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0057, code lost:
    
        r1 = (android.os.PowerManager) r1.getSystemService("power");
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x005f, code lost:
    
        if (r1 == null) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x0065, code lost:
    
        if (r1.isScreenOn() == false) goto L75;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0067, code lost:
    
        r1 = com.google.android.gms.ads.internal.j.C.g;
        r2 = r1.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x006d, code lost:
    
        monitor-enter(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x006e, code lost:
    
        r1 = (com.google.android.gms.internal.ads.K5) r1.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x0072, code lost:
    
        if (r1 == null) goto L41;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x0074, code lost:
    
        r1 = r1.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0076, code lost:
    
        monitor-exit(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x0078, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x007a, code lost:
    
        monitor-exit(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x007b, code lost:
    
        r1 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x007c, code lost:
    
        if (r1 != null) goto L109;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x007e, code lost:
    
        com.google.android.gms.ads.internal.util.client.i.d("ContentFetchThread: no activity. Sleeping.");
        r1 = r8.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0085, code lost:
    
        monitor-enter(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x0086, code lost:
    
        r8.b = true;
        com.google.android.gms.ads.internal.util.client.i.d("ContentFetchThread: paused, pause = true");
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x008d, code lost:
    
        monitor-exit(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0092, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0094, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x009b, code lost:
    
        if (r1.getWindow() == null) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x00a5, code lost:
    
        if (r1.getWindow().getDecorView() == null) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x00a7, code lost:
    
        r3 = r1.getWindow().getDecorView().findViewById(android.R.id.content);
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x00b7, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x00b8, code lost:
    
        com.google.android.gms.ads.internal.j.C.h.h("ContentFetchTask.extractContent", r0);
        com.google.android.gms.ads.internal.util.client.i.d("Failed getting root view of activity. Content not extracted.");
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x00d4, code lost:
    
        throw r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x00ff, code lost:
    
        com.google.android.gms.ads.internal.util.client.i.f("Error in ContentFetchTask", r0);
        com.google.android.gms.ads.internal.j.C.h.h("ContentFetchTask.run", r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x010e, code lost:
    
        com.google.android.gms.ads.internal.util.client.i.f("Error in ContentFetchTask", r0);
     */
    /* JADX WARN: Removed duplicated region for block: B:101:0x0116 A[EXC_TOP_SPLITTER, LOOP:2: B:101:0x0116->B:121:0x0116, LOOP_START, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:111:0x00eb A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00e3 A[Catch: Exception -> 0x0092, InterruptedException -> 0x0094, TryCatch #10 {InterruptedException -> 0x0094, Exception -> 0x0092, blocks: (B:32:0x0067, B:33:0x006d, B:44:0x007e, B:45:0x0085, B:79:0x00f3, B:51:0x0091, B:65:0x00c8, B:63:0x00b8, B:68:0x00d4, B:75:0x00e3, B:76:0x00ea, B:83:0x00fe, B:74:0x00da), top: B:115:0x0067 }] */
    @Override // java.lang.Thread, java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() throws java.lang.InterruptedException {
        /*
            Method dump skipped, instructions count: 298
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.N5.run():void");
    }
}
