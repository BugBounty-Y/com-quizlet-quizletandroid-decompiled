package com.iab.omid.library.pubmatic.walking;

import android.os.Handler;
import android.os.Looper;
import android.view.View;
import com.iab.omid.library.pubmatic.processor.a;
import com.iab.omid.library.pubmatic.utils.f;
import com.iab.omid.library.pubmatic.utils.h;
import com.iab.omid.library.pubmatic.walking.a;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class TreeWalker implements a.InterfaceC0003a {
    private static TreeWalker i = new TreeWalker();
    private static Handler j = new Handler(Looper.getMainLooper());
    private static Handler k = null;
    private static final Runnable l = new b();
    private static final Runnable m = new c();
    private int b;
    private long h;
    private List<TreeWalkerTimeLogger> a = new ArrayList();
    private boolean c = false;
    private final List<com.iab.omid.library.pubmatic.weakreference.a> d = new ArrayList();
    private com.iab.omid.library.pubmatic.walking.a f = new com.iab.omid.library.pubmatic.walking.a();
    private com.iab.omid.library.pubmatic.processor.b e = new com.iab.omid.library.pubmatic.processor.b();
    private com.iab.omid.library.pubmatic.walking.b g = new com.iab.omid.library.pubmatic.walking.b(new com.iab.omid.library.pubmatic.walking.async.c());

    public interface TreeWalkerNanoTimeLogger extends TreeWalkerTimeLogger {
        void onTreeProcessedNano(int i, long j);
    }

    public interface TreeWalkerTimeLogger {
        void onTreeProcessed(int i, long j);
    }

    public class a implements Runnable {
        public a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            TreeWalker.this.g.b();
        }
    }

    public class b implements Runnable {
        @Override // java.lang.Runnable
        public void run() throws JSONException {
            TreeWalker.getInstance().l();
        }
    }

    public class c implements Runnable {
        @Override // java.lang.Runnable
        public void run() {
            if (TreeWalker.k != null) {
                TreeWalker.k.post(TreeWalker.l);
                TreeWalker.k.postDelayed(TreeWalker.m, 200L);
            }
        }
    }

    private void d() {
        a(f.b() - this.h);
    }

    private void e() {
        this.b = 0;
        this.d.clear();
        this.c = false;
        Iterator<com.iab.omid.library.pubmatic.adsession.a> it2 = com.iab.omid.library.pubmatic.internal.c.c().a().iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            } else if (it2.next().e()) {
                this.c = true;
                break;
            }
        }
        this.h = f.b();
    }

    public static TreeWalker getInstance() {
        return i;
    }

    private void i() {
        if (k == null) {
            Handler handler = new Handler(Looper.getMainLooper());
            k = handler;
            handler.post(l);
            k.postDelayed(m, 200L);
        }
    }

    private void k() {
        Handler handler = k;
        if (handler != null) {
            handler.removeCallbacks(m);
            k = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void l() throws JSONException {
        e();
        f();
        d();
    }

    public void addTimeLogger(TreeWalkerTimeLogger treeWalkerTimeLogger) {
        if (this.a.contains(treeWalkerTimeLogger)) {
            return;
        }
        this.a.add(treeWalkerTimeLogger);
    }

    public void f() throws JSONException {
        TreeWalker treeWalker;
        this.f.e();
        long jB = f.b();
        com.iab.omid.library.pubmatic.processor.a aVarA = this.e.a();
        if (this.f.b().size() > 0) {
            Iterator<String> it2 = this.f.b().iterator();
            while (it2.hasNext()) {
                String next = it2.next();
                JSONObject jSONObjectA = aVarA.a(null);
                a(next, this.f.a(next), jSONObjectA);
                com.iab.omid.library.pubmatic.utils.c.b(jSONObjectA);
                HashSet<String> hashSet = new HashSet<>();
                hashSet.add(next);
                this.g.a(jSONObjectA, hashSet, jB);
            }
        }
        if (this.f.c().size() > 0) {
            JSONObject jSONObjectA2 = aVarA.a(null);
            treeWalker = this;
            treeWalker.a(null, aVarA, jSONObjectA2, com.iab.omid.library.pubmatic.walking.c.PARENT_VIEW, false);
            com.iab.omid.library.pubmatic.utils.c.b(jSONObjectA2);
            treeWalker.g.b(jSONObjectA2, treeWalker.f.c(), jB);
            if (treeWalker.c) {
                Iterator<com.iab.omid.library.pubmatic.adsession.a> it3 = com.iab.omid.library.pubmatic.internal.c.c().a().iterator();
                while (it3.hasNext()) {
                    it3.next().a(treeWalker.d);
                }
            }
        } else {
            treeWalker = this;
            treeWalker.g.b();
        }
        treeWalker.f.a();
    }

    public void g() {
        k();
    }

    public void h() {
        i();
    }

    public void j() {
        g();
        this.a.clear();
        j.post(new a());
    }

    public void removeTimeLogger(TreeWalkerTimeLogger treeWalkerTimeLogger) {
        if (this.a.contains(treeWalkerTimeLogger)) {
            this.a.remove(treeWalkerTimeLogger);
        }
    }

    private void a(long j2) {
        if (this.a.size() > 0) {
            for (TreeWalkerTimeLogger treeWalkerTimeLogger : this.a) {
                treeWalkerTimeLogger.onTreeProcessed(this.b, TimeUnit.NANOSECONDS.toMillis(j2));
                if (treeWalkerTimeLogger instanceof TreeWalkerNanoTimeLogger) {
                    ((TreeWalkerNanoTimeLogger) treeWalkerTimeLogger).onTreeProcessedNano(this.b, j2);
                }
            }
        }
    }

    private boolean b(View view, JSONObject jSONObject) throws JSONException {
        String strD = this.f.d(view);
        if (strD == null) {
            return false;
        }
        com.iab.omid.library.pubmatic.utils.c.a(jSONObject, strD);
        com.iab.omid.library.pubmatic.utils.c.a(jSONObject, Boolean.valueOf(this.f.f(view)));
        this.f.d();
        return true;
    }

    private void a(View view, com.iab.omid.library.pubmatic.processor.a aVar, JSONObject jSONObject, com.iab.omid.library.pubmatic.walking.c cVar, boolean z) {
        aVar.a(view, jSONObject, this, cVar == com.iab.omid.library.pubmatic.walking.c.PARENT_VIEW, z);
    }

    @Override // com.iab.omid.library.pubmatic.processor.a.InterfaceC0003a
    public void a(View view, com.iab.omid.library.pubmatic.processor.a aVar, JSONObject jSONObject, boolean z) throws JSONException {
        com.iab.omid.library.pubmatic.walking.c cVarE;
        TreeWalker treeWalker;
        if (h.d(view) && (cVarE = this.f.e(view)) != com.iab.omid.library.pubmatic.walking.c.UNDERLYING_VIEW) {
            JSONObject jSONObjectA = aVar.a(view);
            com.iab.omid.library.pubmatic.utils.c.a(jSONObject, jSONObjectA);
            if (b(view, jSONObjectA)) {
                treeWalker = this;
            } else {
                boolean z2 = z || a(view, jSONObjectA);
                if (this.c && cVarE == com.iab.omid.library.pubmatic.walking.c.OBSTRUCTION_VIEW && !z2) {
                    this.d.add(new com.iab.omid.library.pubmatic.weakreference.a(view));
                }
                treeWalker = this;
                treeWalker.a(view, aVar, jSONObjectA, cVarE, z2);
            }
            treeWalker.b++;
        }
    }

    private void a(String str, View view, JSONObject jSONObject) throws JSONException {
        com.iab.omid.library.pubmatic.processor.a aVarB = this.e.b();
        String strB = this.f.b(str);
        if (strB != null) {
            JSONObject jSONObjectA = aVarB.a(view);
            com.iab.omid.library.pubmatic.utils.c.a(jSONObjectA, str);
            com.iab.omid.library.pubmatic.utils.c.b(jSONObjectA, strB);
            com.iab.omid.library.pubmatic.utils.c.a(jSONObject, jSONObjectA);
        }
    }

    private boolean a(View view, JSONObject jSONObject) throws JSONException {
        a.C0005a c0005aC = this.f.c(view);
        if (c0005aC == null) {
            return false;
        }
        com.iab.omid.library.pubmatic.utils.c.a(jSONObject, c0005aC);
        return true;
    }
}
