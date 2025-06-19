package com.bumptech.glide;

import android.R;
import android.app.Activity;
import android.app.ActivityManager;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.os.Looper;
import android.text.TextUtils;
import android.text.format.Formatter;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.View;
import androidx.appcompat.app.L;
import androidx.collection.C0208f;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import com.bumptech.glide.integration.okhttp3.OkHttpGlideModule;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_common.C;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public class Glide implements ComponentCallbacks2 {
    public static volatile Glide h;
    public static volatile boolean i;
    public final com.bumptech.glide.load.engine.bitmap_recycle.a a;
    public final com.bumptech.glide.load.engine.cache.d b;
    public final e c;
    public final androidx.compose.foundation.lazy.grid.m d;
    public final com.bumptech.glide.manager.l e;
    public final u f;
    public final ArrayList g = new ArrayList();

    public Glide(Context context, com.bumptech.glide.load.engine.l lVar, com.bumptech.glide.load.engine.cache.d dVar, com.bumptech.glide.load.engine.bitmap_recycle.a aVar, androidx.compose.foundation.lazy.grid.m mVar, com.bumptech.glide.manager.l lVar2, u uVar, int i2, com.quizlet.shared.usecase.studiableMetadata.a aVar2, C0208f c0208f, List list, List list2, C c, L l) {
        this.a = aVar;
        this.d = mVar;
        this.b = dVar;
        this.e = lVar2;
        this.f = uVar;
        this.c = new e(context, mVar, new androidx.browser.customtabs.k(this, list2, c), new com.google.mlkit.common.sdkinternal.b(7), aVar2, c0208f, list, lVar, l, i2);
    }

    public static Glide a(Context context) {
        GeneratedAppGlideModule generatedAppGlideModule;
        if (h == null) {
            try {
                generatedAppGlideModule = (GeneratedAppGlideModule) GeneratedAppGlideModuleImpl.class.getDeclaredConstructor(Context.class).newInstance(context.getApplicationContext().getApplicationContext());
            } catch (ClassNotFoundException unused) {
                if (Log.isLoggable("Glide", 5)) {
                    Log.w("Glide", "Failed to find GeneratedAppGlideModule. You should include an annotationProcessor compile dependency on com.github.bumptech.glide:compiler in your application and a @GlideModule annotated AppGlideModule implementation or LibraryGlideModules will be silently ignored");
                }
                generatedAppGlideModule = null;
            } catch (IllegalAccessException e) {
                throw new IllegalStateException("GeneratedAppGlideModuleImpl is implemented incorrectly. If you've manually implemented this class, remove your implementation. The Annotation processor will generate a correct implementation.", e);
            } catch (InstantiationException e2) {
                throw new IllegalStateException("GeneratedAppGlideModuleImpl is implemented incorrectly. If you've manually implemented this class, remove your implementation. The Annotation processor will generate a correct implementation.", e2);
            } catch (NoSuchMethodException e3) {
                throw new IllegalStateException("GeneratedAppGlideModuleImpl is implemented incorrectly. If you've manually implemented this class, remove your implementation. The Annotation processor will generate a correct implementation.", e3);
            } catch (InvocationTargetException e4) {
                throw new IllegalStateException("GeneratedAppGlideModuleImpl is implemented incorrectly. If you've manually implemented this class, remove your implementation. The Annotation processor will generate a correct implementation.", e4);
            }
            synchronized (Glide.class) {
                if (h == null) {
                    if (i) {
                        throw new IllegalStateException("Glide has been called recursively, this is probably an internal library error!");
                    }
                    i = true;
                    try {
                        b(context, generatedAppGlideModule);
                        i = false;
                    } catch (Throwable th) {
                        i = false;
                        throw th;
                    }
                }
            }
        }
        return h;
    }

    public static void b(Context context, GeneratedAppGlideModule generatedAppGlideModule) throws PackageManager.NameNotFoundException {
        List list;
        int i2 = 6;
        d dVar = new d();
        Context applicationContext = context.getApplicationContext();
        List list2 = Collections.EMPTY_LIST;
        if (generatedAppGlideModule == null || !(generatedAppGlideModule instanceof GeneratedAppGlideModuleImpl)) {
            com.bumptech.glide.module.a aVar = new com.bumptech.glide.module.a(applicationContext);
            Log.isLoggable("ManifestParser", 3);
            ArrayList arrayList = new ArrayList();
            try {
                Context context2 = aVar.a;
                ApplicationInfo applicationInfo = context2.getPackageManager().getApplicationInfo(context2.getPackageName(), 128);
                if (applicationInfo == null || applicationInfo.metaData == null) {
                    Log.isLoggable("ManifestParser", 3);
                } else {
                    if (Log.isLoggable("ManifestParser", 2)) {
                        Objects.toString(applicationInfo.metaData);
                    }
                    for (String str : applicationInfo.metaData.keySet()) {
                        if ("GlideModule".equals(applicationInfo.metaData.get(str))) {
                            arrayList.add(com.bumptech.glide.module.a.a(str));
                            Log.isLoggable("ManifestParser", 3);
                        }
                    }
                    Log.isLoggable("ManifestParser", 3);
                }
            } catch (PackageManager.NameNotFoundException e) {
                if (Log.isLoggable("ManifestParser", 6)) {
                    Log.e("ManifestParser", "Failed to parse glide modules", e);
                }
            }
            list = arrayList;
        } else {
            list = list2;
        }
        if (generatedAppGlideModule != null && !new HashSet().isEmpty()) {
            HashSet hashSet = new HashSet();
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                OkHttpGlideModule okHttpGlideModule = (OkHttpGlideModule) it2.next();
                if (hashSet.contains(okHttpGlideModule.getClass())) {
                    if (Log.isLoggable("Glide", 3)) {
                        okHttpGlideModule.toString();
                    }
                    it2.remove();
                }
            }
        }
        if (Log.isLoggable("Glide", 3)) {
            Iterator it3 = list.iterator();
            while (it3.hasNext()) {
                ((OkHttpGlideModule) it3.next()).getClass().toString();
            }
        }
        Iterator it4 = list.iterator();
        while (it4.hasNext()) {
            ((OkHttpGlideModule) it4.next()).getClass();
        }
        if (generatedAppGlideModule != null) {
            generatedAppGlideModule.a(applicationContext, dVar);
        }
        if (dVar.g == null) {
            com.bumptech.glide.load.engine.executor.b bVar = new com.bumptech.glide.load.engine.executor.b();
            if (com.bumptech.glide.load.engine.executor.e.c == 0) {
                com.bumptech.glide.load.engine.executor.e.c = Math.min(4, Runtime.getRuntime().availableProcessors());
            }
            int i3 = com.bumptech.glide.load.engine.executor.e.c;
            if (TextUtils.isEmpty("source")) {
                throw new IllegalArgumentException("Name must be non-null and non-empty, but given: source");
            }
            dVar.g = new com.bumptech.glide.load.engine.executor.e(new ThreadPoolExecutor(i3, i3, 0L, TimeUnit.MILLISECONDS, new PriorityBlockingQueue(), new com.bumptech.glide.load.engine.executor.c(bVar, "source", false)));
        }
        if (dVar.h == null) {
            int i4 = com.bumptech.glide.load.engine.executor.e.c;
            com.bumptech.glide.load.engine.executor.b bVar2 = new com.bumptech.glide.load.engine.executor.b();
            if (TextUtils.isEmpty("disk-cache")) {
                throw new IllegalArgumentException("Name must be non-null and non-empty, but given: disk-cache");
            }
            dVar.h = new com.bumptech.glide.load.engine.executor.e(new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, new PriorityBlockingQueue(), new com.bumptech.glide.load.engine.executor.c(bVar2, "disk-cache", true)));
        }
        if (dVar.n == null) {
            if (com.bumptech.glide.load.engine.executor.e.c == 0) {
                com.bumptech.glide.load.engine.executor.e.c = Math.min(4, Runtime.getRuntime().availableProcessors());
            }
            int i5 = com.bumptech.glide.load.engine.executor.e.c >= 4 ? 2 : 1;
            com.bumptech.glide.load.engine.executor.b bVar3 = new com.bumptech.glide.load.engine.executor.b();
            if (TextUtils.isEmpty("animation")) {
                throw new IllegalArgumentException("Name must be non-null and non-empty, but given: animation");
            }
            dVar.n = new com.bumptech.glide.load.engine.executor.e(new ThreadPoolExecutor(i5, i5, 0L, TimeUnit.MILLISECONDS, new PriorityBlockingQueue(), new com.bumptech.glide.load.engine.executor.c(bVar3, "animation", true)));
        }
        if (dVar.j == null) {
            com.bumptech.glide.load.engine.cache.e eVar = new com.bumptech.glide.load.engine.cache.e(applicationContext);
            com.bumptech.glide.load.engine.cache.f fVar = new com.bumptech.glide.load.engine.cache.f();
            Context context3 = eVar.a;
            ActivityManager activityManager = eVar.b;
            int i6 = activityManager.isLowRamDevice() ? 2097152 : 4194304;
            fVar.c = i6;
            int iRound = Math.round(activityManager.getMemoryClass() * 1048576 * (activityManager.isLowRamDevice() ? 0.33f : 0.4f));
            DisplayMetrics displayMetrics = (DisplayMetrics) eVar.c.b;
            float f = displayMetrics.widthPixels * displayMetrics.heightPixels * 4;
            float f2 = eVar.d;
            int iRound2 = Math.round(f * f2);
            int iRound3 = Math.round(f * 2.0f);
            int i7 = iRound - i6;
            if (iRound3 + iRound2 <= i7) {
                fVar.b = iRound3;
                fVar.a = iRound2;
            } else {
                float f3 = i7 / (f2 + 2.0f);
                fVar.b = Math.round(2.0f * f3);
                fVar.a = Math.round(f3 * f2);
            }
            if (Log.isLoggable("MemorySizeCalculator", 3)) {
                Formatter.formatFileSize(context3, fVar.b);
                Formatter.formatFileSize(context3, fVar.a);
                Formatter.formatFileSize(context3, i6);
                Formatter.formatFileSize(context3, iRound);
                activityManager.getMemoryClass();
                activityManager.isLowRamDevice();
            }
            dVar.j = fVar;
        }
        if (dVar.k == null) {
            dVar.k = new u(7);
        }
        if (dVar.d == null) {
            int i8 = dVar.j.a;
            if (i8 > 0) {
                dVar.d = new com.bumptech.glide.load.engine.bitmap_recycle.f(i8);
            } else {
                dVar.d = new com.google.mlkit.common.internal.model.a(i2);
            }
        }
        if (dVar.e == null) {
            dVar.e = new androidx.compose.foundation.lazy.grid.m(dVar.j.c, 2);
        }
        if (dVar.f == null) {
            dVar.f = new com.bumptech.glide.load.engine.cache.d(1, dVar.j.b);
        }
        if (dVar.i == null) {
            dVar.i = new com.bumptech.glide.load.engine.cache.c(applicationContext);
        }
        if (dVar.c == null) {
            dVar.c = new com.bumptech.glide.load.engine.l(dVar.f, dVar.i, dVar.h, dVar.g, new com.bumptech.glide.load.engine.executor.e(new ThreadPoolExecutor(0, SubsamplingScaleImageView.TILE_SIZE_AUTO, com.bumptech.glide.load.engine.executor.e.b, TimeUnit.MILLISECONDS, new SynchronousQueue(), new com.bumptech.glide.load.engine.executor.c(new com.bumptech.glide.load.engine.executor.b(), "source-unlimited", false))), dVar.n);
        }
        List list3 = dVar.o;
        if (list3 == null) {
            dVar.o = Collections.EMPTY_LIST;
        } else {
            dVar.o = Collections.unmodifiableList(list3);
        }
        f fVar2 = dVar.b;
        fVar2.getClass();
        Glide glide = new Glide(applicationContext, dVar.c, dVar.f, dVar.d, dVar.e, new com.bumptech.glide.manager.l(), dVar.k, dVar.l, dVar.m, dVar.a, dVar.o, list, generatedAppGlideModule, new L(fVar2));
        applicationContext.registerComponentCallbacks(glide);
        h = glide;
    }

    public static m c(Context context) {
        com.bumptech.glide.util.f.c(context, "You cannot start a load on a not yet attached View or a Fragment where getActivity() returns null (which usually occurs when getActivity() is called before the Fragment is attached or after the Fragment is destroyed).");
        return a(context).e.c(context);
    }

    public static m d(View view) {
        Context context = view.getContext();
        com.bumptech.glide.util.f.c(context, "You cannot start a load on a not yet attached View or a Fragment where getActivity() returns null (which usually occurs when getActivity() is called before the Fragment is attached or after the Fragment is destroyed).");
        com.bumptech.glide.manager.l lVar = a(context).e;
        lVar.getClass();
        char[] cArr = com.bumptech.glide.util.m.a;
        if (!(Looper.myLooper() == Looper.getMainLooper())) {
            return lVar.c(view.getContext().getApplicationContext());
        }
        com.bumptech.glide.util.f.c(view.getContext(), "Unable to obtain a request manager for a view without a Context");
        Activity activityA = com.bumptech.glide.manager.l.a(view.getContext());
        if (activityA != null && (activityA instanceof I)) {
            I i2 = (I) activityA;
            C0208f c0208f = lVar.b;
            c0208f.clear();
            com.bumptech.glide.manager.l.b(i2.getSupportFragmentManager().c.f(), c0208f);
            View viewFindViewById = i2.findViewById(R.id.content);
            Fragment fragment = null;
            while (!view.equals(viewFindViewById) && (fragment = (Fragment) c0208f.get(view)) == null && (view.getParent() instanceof View)) {
                view = (View) view.getParent();
            }
            c0208f.clear();
            if (fragment == null) {
                return lVar.d(i2);
            }
            com.bumptech.glide.util.f.c(fragment.getContext(), "You cannot start a load on a fragment before it is attached or after it is destroyed");
            if (!(Looper.myLooper() == Looper.getMainLooper())) {
                return lVar.c(fragment.getContext().getApplicationContext());
            }
            if (fragment.getActivity() != null) {
                lVar.c.c(fragment.getActivity());
            }
            AbstractC1136h0 childFragmentManager = fragment.getChildFragmentManager();
            Context context2 = fragment.getContext();
            return lVar.d.r(context2, a(context2.getApplicationContext()), fragment.getLifecycle(), childFragmentManager, fragment.isVisible());
        }
        return lVar.c(view.getContext().getApplicationContext());
    }

    @Override // android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
    }

    @Override // android.content.ComponentCallbacks
    public final void onLowMemory() {
        com.bumptech.glide.util.m.a();
        this.b.g(0L);
        this.a.e();
        androidx.compose.foundation.lazy.grid.m mVar = this.d;
        synchronized (mVar) {
            mVar.e(0);
        }
    }

    @Override // android.content.ComponentCallbacks2
    public final void onTrimMemory(int i2) {
        long j;
        com.bumptech.glide.util.m.a();
        synchronized (this.g) {
            try {
                Iterator it2 = this.g.iterator();
                while (it2.hasNext()) {
                    ((m) it2.next()).getClass();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        com.bumptech.glide.load.engine.cache.d dVar = this.b;
        dVar.getClass();
        if (i2 >= 40) {
            dVar.g(0L);
        } else if (i2 >= 20 || i2 == 15) {
            synchronized (dVar) {
                j = dVar.b;
            }
            dVar.g(j / 2);
        }
        this.a.d(i2);
        androidx.compose.foundation.lazy.grid.m mVar = this.d;
        synchronized (mVar) {
            if (i2 >= 40) {
                synchronized (mVar) {
                    mVar.e(0);
                }
            } else if (i2 >= 20 || i2 == 15) {
                mVar.e(mVar.a / 2);
            }
        }
    }
}
