package androidx.appcompat.app;

import android.R;
import android.app.Activity;
import android.app.Dialog;
import android.app.UiModeManager;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.os.LocaleList;
import android.text.TextUtils;
import android.util.AndroidRuntimeException;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;
import androidx.appcompat.widget.ActionBarContextView;
import androidx.appcompat.widget.ActionBarOverlayLayout;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.C0087h;
import androidx.appcompat.widget.C0095l;
import androidx.appcompat.widget.C0112u;
import androidx.appcompat.widget.C1;
import androidx.appcompat.widget.ContentFrameLayout;
import androidx.appcompat.widget.InterfaceC0094k0;
import androidx.appcompat.widget.x1;
import androidx.collection.V;
import androidx.core.app.AbstractC1019f;
import androidx.core.view.C1043d0;
import com.comscore.streaming.ContentType;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class B extends AbstractC0061q implements androidx.appcompat.view.menu.l, LayoutInflater.Factory2 {
    public static final V r1 = new V(0);
    public static final int[] s1 = {R.attr.windowBackground};
    public static final boolean t1 = !"robolectric".equals(Build.FINGERPRINT);
    public ViewGroup A;
    public TextView B;
    public View C;
    public boolean D;
    public boolean E;
    public boolean F;
    public boolean G;
    public boolean H;
    public boolean I;
    public boolean J;
    public boolean K;
    public A[] L;
    public A M;
    public boolean V;
    public boolean W;
    public boolean X;
    public boolean Y;
    public Configuration Z;
    public final int c1;
    public int d1;
    public int e1;
    public boolean f1;
    public x g1;
    public x h1;
    public boolean i1;
    public final Object j;
    public int j1;
    public final Context k;
    public Window l;
    public boolean l1;
    public w m;
    public Rect m1;
    public final Object n;
    public Rect n1;
    public com.bumptech.glide.c o;
    public G o1;
    public androidx.appcompat.view.i p;
    public OnBackInvokedDispatcher p1;
    public CharSequence q;
    public OnBackInvokedCallback q1;
    public InterfaceC0094k0 r;
    public com.google.android.gms.auth.api.signin.internal.h s;
    public com.google.android.gms.internal.instantapps.a t;
    public androidx.appcompat.view.b u;
    public ActionBarContextView v;
    public PopupWindow w;
    public r x;
    public boolean z;
    public C1043d0 y = null;
    public final r k1 = new r(this, 0);

    public B(Context context, Window window, InterfaceC0056l interfaceC0056l, Object obj) {
        AbstractActivityC0055k abstractActivityC0055k = null;
        this.c1 = -100;
        this.k = context;
        this.n = interfaceC0056l;
        this.j = obj;
        if (obj instanceof Dialog) {
            while (true) {
                if (context != null) {
                    if (!(context instanceof AbstractActivityC0055k)) {
                        if (!(context instanceof ContextWrapper)) {
                            break;
                        } else {
                            context = ((ContextWrapper) context).getBaseContext();
                        }
                    } else {
                        abstractActivityC0055k = (AbstractActivityC0055k) context;
                        break;
                    }
                } else {
                    break;
                }
            }
            if (abstractActivityC0055k != null) {
                this.c1 = ((B) abstractActivityC0055k.q()).c1;
            }
        }
        if (this.c1 == -100) {
            V v = r1;
            Integer num = (Integer) v.get(this.j.getClass().getName());
            if (num != null) {
                this.c1 = num.intValue();
                v.remove(this.j.getClass().getName());
            }
        }
        if (window != null) {
            n(window);
        }
        C0112u.d();
    }

    public static androidx.core.os.f o(Context context) {
        androidx.core.os.f fVar;
        androidx.core.os.f fVar2;
        if (Build.VERSION.SDK_INT >= 33 || (fVar = AbstractC0061q.c) == null) {
            return null;
        }
        androidx.core.os.f fVarB = u.b(context.getApplicationContext().getResources().getConfiguration());
        if (fVar.a.a.isEmpty()) {
            fVar2 = androidx.core.os.f.b;
        } else {
            LinkedHashSet linkedHashSet = new LinkedHashSet();
            int i = 0;
            while (i < fVarB.c() + fVar.c()) {
                Locale localeB = i < fVar.c() ? fVar.b(i) : fVarB.b(i - fVar.c());
                if (localeB != null) {
                    linkedHashSet.add(localeB);
                }
                i++;
            }
            fVar2 = new androidx.core.os.f(new androidx.core.os.g(new LocaleList((Locale[]) linkedHashSet.toArray(new Locale[linkedHashSet.size()]))));
        }
        return fVar2.a.a.isEmpty() ? fVarB : fVar2;
    }

    public static Configuration t(Context context, int i, androidx.core.os.f fVar, Configuration configuration, boolean z) {
        int i2 = i != 1 ? i != 2 ? z ? 0 : context.getApplicationContext().getResources().getConfiguration().uiMode & 48 : 32 : 16;
        Configuration configuration2 = new Configuration();
        configuration2.fontScale = DefinitionKt.NO_Float_VALUE;
        if (configuration != null) {
            configuration2.setTo(configuration);
        }
        configuration2.uiMode = i2 | (configuration2.uiMode & (-49));
        if (fVar != null) {
            u.d(configuration2, fVar);
        }
        return configuration2;
    }

    public final void A() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        w();
        if (this.F && this.o == null) {
            Object obj = this.j;
            if (obj instanceof Activity) {
                this.o = new T((Activity) obj, this.G);
            } else if (obj instanceof Dialog) {
                this.o = new T((Dialog) obj);
            }
            com.bumptech.glide.c cVar = this.o;
            if (cVar != null) {
                cVar.r(this.l1);
            }
        }
    }

    public final void B(int i) {
        this.j1 = (1 << i) | this.j1;
        if (this.i1) {
            return;
        }
        View decorView = this.l.getDecorView();
        r rVar = this.k1;
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        decorView.postOnAnimation(rVar);
        this.i1 = true;
    }

    public final int C(Context context, int i) {
        if (i != -100) {
            if (i != -1) {
                if (i != 0) {
                    if (i != 1 && i != 2) {
                        if (i != 3) {
                            throw new IllegalStateException("Unknown value set for night mode. Please use one of the MODE_NIGHT values from AppCompatDelegate.");
                        }
                        if (this.h1 == null) {
                            this.h1 = new x(this, context);
                        }
                        return this.h1.f();
                    }
                } else if (((UiModeManager) context.getApplicationContext().getSystemService("uimode")).getNightMode() != 0) {
                    return y(context).f();
                }
            }
            return i;
        }
        return -1;
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0048, code lost:
    
        if (r6.i() != false) goto L20;
     */
    @Override // androidx.appcompat.view.menu.l
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void D(androidx.appcompat.view.menu.n r6) throws java.lang.IllegalAccessException, java.lang.NoSuchMethodException, java.lang.SecurityException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            r5 = this;
            androidx.appcompat.widget.k0 r6 = r5.r
            r0 = 1
            r1 = 0
            if (r6 == 0) goto Ld3
            androidx.appcompat.widget.ActionBarOverlayLayout r6 = (androidx.appcompat.widget.ActionBarOverlayLayout) r6
            r6.k()
            androidx.appcompat.widget.l0 r6 = r6.e
            androidx.appcompat.widget.x1 r6 = (androidx.appcompat.widget.x1) r6
            androidx.appcompat.widget.Toolbar r6 = r6.a
            int r2 = r6.getVisibility()
            if (r2 != 0) goto Ld3
            androidx.appcompat.widget.ActionMenuView r6 = r6.a
            if (r6 == 0) goto Ld3
            boolean r6 = r6.s
            if (r6 == 0) goto Ld3
            android.content.Context r6 = r5.k
            android.view.ViewConfiguration r6 = android.view.ViewConfiguration.get(r6)
            boolean r6 = r6.hasPermanentMenuKey()
            if (r6 == 0) goto L4a
            androidx.appcompat.widget.k0 r6 = r5.r
            androidx.appcompat.widget.ActionBarOverlayLayout r6 = (androidx.appcompat.widget.ActionBarOverlayLayout) r6
            r6.k()
            androidx.appcompat.widget.l0 r6 = r6.e
            androidx.appcompat.widget.x1 r6 = (androidx.appcompat.widget.x1) r6
            androidx.appcompat.widget.Toolbar r6 = r6.a
            androidx.appcompat.widget.ActionMenuView r6 = r6.a
            if (r6 == 0) goto Ld3
            androidx.appcompat.widget.l r6 = r6.t
            if (r6 == 0) goto Ld3
            androidx.appcompat.widget.j r2 = r6.u
            if (r2 != 0) goto L4a
            boolean r6 = r6.i()
            if (r6 == 0) goto Ld3
        L4a:
            android.view.Window r6 = r5.l
            android.view.Window$Callback r6 = r6.getCallback()
            androidx.appcompat.widget.k0 r2 = r5.r
            androidx.appcompat.widget.ActionBarOverlayLayout r2 = (androidx.appcompat.widget.ActionBarOverlayLayout) r2
            r2.k()
            androidx.appcompat.widget.l0 r2 = r2.e
            androidx.appcompat.widget.x1 r2 = (androidx.appcompat.widget.x1) r2
            androidx.appcompat.widget.Toolbar r2 = r2.a
            boolean r2 = r2.p()
            r3 = 108(0x6c, float:1.51E-43)
            if (r2 == 0) goto L8c
            androidx.appcompat.widget.k0 r0 = r5.r
            androidx.appcompat.widget.ActionBarOverlayLayout r0 = (androidx.appcompat.widget.ActionBarOverlayLayout) r0
            r0.k()
            androidx.appcompat.widget.l0 r0 = r0.e
            androidx.appcompat.widget.x1 r0 = (androidx.appcompat.widget.x1) r0
            androidx.appcompat.widget.Toolbar r0 = r0.a
            androidx.appcompat.widget.ActionMenuView r0 = r0.a
            if (r0 == 0) goto L7e
            androidx.appcompat.widget.l r0 = r0.t
            if (r0 == 0) goto L7e
            boolean r0 = r0.f()
        L7e:
            boolean r0 = r5.Y
            if (r0 != 0) goto Ld2
            androidx.appcompat.app.A r0 = r5.z(r1)
            androidx.appcompat.view.menu.n r0 = r0.h
            r6.onPanelClosed(r3, r0)
            return
        L8c:
            if (r6 == 0) goto Ld2
            boolean r2 = r5.Y
            if (r2 != 0) goto Ld2
            boolean r2 = r5.i1
            if (r2 == 0) goto La9
            int r2 = r5.j1
            r0 = r0 & r2
            if (r0 == 0) goto La9
            android.view.Window r0 = r5.l
            android.view.View r0 = r0.getDecorView()
            androidx.appcompat.app.r r2 = r5.k1
            r0.removeCallbacks(r2)
            r2.run()
        La9:
            androidx.appcompat.app.A r0 = r5.z(r1)
            androidx.appcompat.view.menu.n r2 = r0.h
            if (r2 == 0) goto Ld2
            boolean r4 = r0.o
            if (r4 != 0) goto Ld2
            android.view.View r4 = r0.g
            boolean r1 = r6.onPreparePanel(r1, r4, r2)
            if (r1 == 0) goto Ld2
            androidx.appcompat.view.menu.n r0 = r0.h
            r6.onMenuOpened(r3, r0)
            androidx.appcompat.widget.k0 r6 = r5.r
            androidx.appcompat.widget.ActionBarOverlayLayout r6 = (androidx.appcompat.widget.ActionBarOverlayLayout) r6
            r6.k()
            androidx.appcompat.widget.l0 r6 = r6.e
            androidx.appcompat.widget.x1 r6 = (androidx.appcompat.widget.x1) r6
            androidx.appcompat.widget.Toolbar r6 = r6.a
            r6.v()
        Ld2:
            return
        Ld3:
            androidx.appcompat.app.A r6 = r5.z(r1)
            r6.n = r0
            r5.s(r6, r1)
            r0 = 0
            r5.F(r6, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.B.D(androidx.appcompat.view.menu.n):void");
    }

    public final boolean E() {
        boolean z = this.V;
        this.V = false;
        A aZ = z(0);
        if (!aZ.m) {
            androidx.appcompat.view.b bVar = this.u;
            if (bVar != null) {
                bVar.a();
                return true;
            }
            A();
            com.bumptech.glide.c cVar = this.o;
            if (cVar == null || !cVar.g()) {
                return false;
            }
        } else if (!z) {
            s(aZ, true);
            return true;
        }
        return true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:87:0x0176, code lost:
    
        if (r3.f.getCount() > 0) goto L88;
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x01d3  */
    /* JADX WARN: Removed duplicated region for block: B:105:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void F(androidx.appcompat.app.A r18, android.view.KeyEvent r19) throws java.lang.IllegalAccessException, java.lang.NoSuchMethodException, java.lang.SecurityException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 474
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.B.F(androidx.appcompat.app.A, android.view.KeyEvent):void");
    }

    public final boolean G(A a, int i, KeyEvent keyEvent) {
        androidx.appcompat.view.menu.n nVar;
        if (keyEvent.isSystem()) {
            return false;
        }
        if ((a.k || H(a, keyEvent)) && (nVar = a.h) != null) {
            return nVar.performShortcut(i, keyEvent, 1);
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:62:0x00d8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean H(androidx.appcompat.app.A r13, android.view.KeyEvent r14) {
        /*
            Method dump skipped, instructions count: 369
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.B.H(androidx.appcompat.app.A, android.view.KeyEvent):boolean");
    }

    public final void I() {
        if (this.z) {
            throw new AndroidRuntimeException("Window feature must be requested before adding content");
        }
    }

    public final void J() {
        OnBackInvokedCallback onBackInvokedCallback;
        if (Build.VERSION.SDK_INT >= 33) {
            boolean z = false;
            if (this.p1 != null && (z(0).m || this.u != null)) {
                z = true;
            }
            if (z && this.q1 == null) {
                this.q1 = v.b(this.p1, this);
            } else {
                if (z || (onBackInvokedCallback = this.q1) == null) {
                    return;
                }
                v.c(this.p1, onBackInvokedCallback);
                this.q1 = null;
            }
        }
    }

    @Override // androidx.appcompat.app.AbstractC0061q
    public final void a() {
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(this.k);
        if (layoutInflaterFrom.getFactory() == null) {
            layoutInflaterFrom.setFactory2(this);
        } else {
            if (layoutInflaterFrom.getFactory2() instanceof B) {
                return;
            }
            Log.i("AppCompatDelegate", "The Activity's LayoutInflater already has a Factory installed so we can not install AppCompat's");
        }
    }

    @Override // androidx.appcompat.app.AbstractC0061q
    public final void b() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        if (this.o != null) {
            A();
            if (this.o.l()) {
                return;
            }
            B(0);
        }
    }

    @Override // androidx.appcompat.app.AbstractC0061q
    public final void d() throws PackageManager.NameNotFoundException {
        String strC;
        this.W = true;
        m(false, true);
        x();
        Object obj = this.j;
        if (obj instanceof Activity) {
            try {
                Activity activity = (Activity) obj;
                try {
                    strC = AbstractC1019f.c(activity, activity.getComponentName());
                } catch (PackageManager.NameNotFoundException e) {
                    throw new IllegalArgumentException(e);
                }
            } catch (IllegalArgumentException unused) {
                strC = null;
            }
            if (strC != null) {
                com.bumptech.glide.c cVar = this.o;
                if (cVar == null) {
                    this.l1 = true;
                } else {
                    cVar.r(true);
                }
            }
            synchronized (AbstractC0061q.h) {
                AbstractC0061q.f(this);
                AbstractC0061q.g.add(new WeakReference(this));
            }
        }
        this.Z = new Configuration(this.k.getResources().getConfiguration());
        this.X = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x004d  */
    @Override // androidx.appcompat.app.AbstractC0061q
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e() {
        /*
            r3 = this;
            java.lang.Object r0 = r3.j
            boolean r0 = r0 instanceof android.app.Activity
            if (r0 == 0) goto L11
            java.lang.Object r0 = androidx.appcompat.app.AbstractC0061q.h
            monitor-enter(r0)
            androidx.appcompat.app.AbstractC0061q.f(r3)     // Catch: java.lang.Throwable -> Le
            monitor-exit(r0)     // Catch: java.lang.Throwable -> Le
            goto L11
        Le:
            r1 = move-exception
            monitor-exit(r0)     // Catch: java.lang.Throwable -> Le
            throw r1
        L11:
            boolean r0 = r3.i1
            if (r0 == 0) goto L20
            android.view.Window r0 = r3.l
            android.view.View r0 = r0.getDecorView()
            androidx.appcompat.app.r r1 = r3.k1
            r0.removeCallbacks(r1)
        L20:
            r0 = 1
            r3.Y = r0
            int r0 = r3.c1
            r1 = -100
            if (r0 == r1) goto L4d
            java.lang.Object r0 = r3.j
            boolean r1 = r0 instanceof android.app.Activity
            if (r1 == 0) goto L4d
            android.app.Activity r0 = (android.app.Activity) r0
            boolean r0 = r0.isChangingConfigurations()
            if (r0 == 0) goto L4d
            androidx.collection.V r0 = androidx.appcompat.app.B.r1
            java.lang.Object r1 = r3.j
            java.lang.Class r1 = r1.getClass()
            java.lang.String r1 = r1.getName()
            int r2 = r3.c1
            java.lang.Integer r2 = java.lang.Integer.valueOf(r2)
            r0.put(r1, r2)
            goto L5c
        L4d:
            androidx.collection.V r0 = androidx.appcompat.app.B.r1
            java.lang.Object r1 = r3.j
            java.lang.Class r1 = r1.getClass()
            java.lang.String r1 = r1.getName()
            r0.remove(r1)
        L5c:
            com.bumptech.glide.c r0 = r3.o
            if (r0 == 0) goto L63
            r0.n()
        L63:
            androidx.appcompat.app.x r0 = r3.g1
            if (r0 == 0) goto L6a
            r0.c()
        L6a:
            androidx.appcompat.app.x r0 = r3.h1
            if (r0 == 0) goto L71
            r0.c()
        L71:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.B.e():void");
    }

    @Override // androidx.appcompat.app.AbstractC0061q
    public final boolean g(int i) {
        if (i == 8) {
            Log.i("AppCompatDelegate", "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR id when requesting this feature.");
            i = 108;
        } else if (i == 9) {
            Log.i("AppCompatDelegate", "You should now use the AppCompatDelegate.FEATURE_SUPPORT_ACTION_BAR_OVERLAY id when requesting this feature.");
            i = 109;
        }
        if (this.J && i == 108) {
            return false;
        }
        if (this.F && i == 1) {
            this.F = false;
        }
        if (i == 1) {
            I();
            this.J = true;
            return true;
        }
        if (i == 2) {
            I();
            this.D = true;
            return true;
        }
        if (i == 5) {
            I();
            this.E = true;
            return true;
        }
        if (i == 10) {
            I();
            this.H = true;
            return true;
        }
        if (i == 108) {
            I();
            this.F = true;
            return true;
        }
        if (i != 109) {
            return this.l.requestFeature(i);
        }
        I();
        this.G = true;
        return true;
    }

    @Override // androidx.appcompat.app.AbstractC0061q
    public final void h(int i) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        w();
        ViewGroup viewGroup = (ViewGroup) this.A.findViewById(R.id.content);
        viewGroup.removeAllViews();
        LayoutInflater.from(this.k).inflate(i, viewGroup);
        this.m.b(this.l.getCallback());
    }

    @Override // androidx.appcompat.app.AbstractC0061q
    public final void i(View view) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        w();
        ViewGroup viewGroup = (ViewGroup) this.A.findViewById(R.id.content);
        viewGroup.removeAllViews();
        viewGroup.addView(view);
        this.m.b(this.l.getCallback());
    }

    @Override // androidx.appcompat.app.AbstractC0061q
    public final void j(View view, ViewGroup.LayoutParams layoutParams) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        w();
        ViewGroup viewGroup = (ViewGroup) this.A.findViewById(R.id.content);
        viewGroup.removeAllViews();
        viewGroup.addView(view, layoutParams);
        this.m.b(this.l.getCallback());
    }

    @Override // androidx.appcompat.app.AbstractC0061q
    public final void l(CharSequence charSequence) {
        this.q = charSequence;
        InterfaceC0094k0 interfaceC0094k0 = this.r;
        if (interfaceC0094k0 != null) {
            interfaceC0094k0.setWindowTitle(charSequence);
            return;
        }
        com.bumptech.glide.c cVar = this.o;
        if (cVar != null) {
            cVar.B(charSequence);
            return;
        }
        TextView textView = this.B;
        if (textView != null) {
            textView.setText(charSequence);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00f0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean m(boolean r13, boolean r14) throws android.content.pm.PackageManager.NameNotFoundException {
        /*
            Method dump skipped, instructions count: 428
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.B.m(boolean, boolean):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x005a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void n(android.view.Window r4) {
        /*
            r3 = this;
            android.view.Window r0 = r3.l
            java.lang.String r1 = "AppCompat has already installed itself into the Window"
            if (r0 != 0) goto L66
            android.view.Window$Callback r0 = r4.getCallback()
            boolean r2 = r0 instanceof androidx.appcompat.app.w
            if (r2 != 0) goto L60
            androidx.appcompat.app.w r1 = new androidx.appcompat.app.w
            r1.<init>(r3, r0)
            r3.m = r1
            r4.setCallback(r1)
            int[] r0 = androidx.appcompat.app.B.s1
            android.content.Context r1 = r3.k
            r2 = 0
            com.quizlet.data.repository.classfolder.e r0 = com.quizlet.data.repository.classfolder.e.l(r1, r2, r0)
            r1 = 0
            android.graphics.drawable.Drawable r1 = r0.h(r1)
            if (r1 == 0) goto L2b
            r4.setBackgroundDrawable(r1)
        L2b:
            r0.n()
            r3.l = r4
            int r4 = android.os.Build.VERSION.SDK_INT
            r0 = 33
            if (r4 < r0) goto L5f
            android.window.OnBackInvokedDispatcher r4 = r3.p1
            if (r4 != 0) goto L5f
            if (r4 == 0) goto L45
            android.window.OnBackInvokedCallback r0 = r3.q1
            if (r0 == 0) goto L45
            androidx.appcompat.app.v.c(r4, r0)
            r3.q1 = r2
        L45:
            java.lang.Object r4 = r3.j
            boolean r0 = r4 instanceof android.app.Activity
            if (r0 == 0) goto L5a
            android.app.Activity r4 = (android.app.Activity) r4
            android.view.Window r0 = r4.getWindow()
            if (r0 == 0) goto L5a
            android.window.OnBackInvokedDispatcher r4 = androidx.appcompat.app.v.a(r4)
            r3.p1 = r4
            goto L5c
        L5a:
            r3.p1 = r2
        L5c:
            r3.J()
        L5f:
            return
        L60:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            r4.<init>(r1)
            throw r4
        L66:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            r4.<init>(r1)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.B.n(android.view.Window):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:24:0x009d  */
    @Override // android.view.LayoutInflater.Factory2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View onCreateView(android.view.View r18, java.lang.String r19, android.content.Context r20, android.util.AttributeSet r21) {
        /*
            Method dump skipped, instructions count: 712
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.B.onCreateView(android.view.View, java.lang.String, android.content.Context, android.util.AttributeSet):android.view.View");
    }

    public final void p(int i, A a, androidx.appcompat.view.menu.n nVar) {
        if (nVar == null) {
            if (a == null && i >= 0) {
                A[] aArr = this.L;
                if (i < aArr.length) {
                    a = aArr[i];
                }
            }
            if (a != null) {
                nVar = a.h;
            }
        }
        if ((a == null || a.m) && !this.Y) {
            w wVar = this.m;
            Window.Callback callback = this.l.getCallback();
            wVar.getClass();
            try {
                wVar.d = true;
                callback.onPanelClosed(i, nVar);
            } finally {
                wVar.d = false;
            }
        }
    }

    public final void q(androidx.appcompat.view.menu.n nVar) {
        C0095l c0095l;
        if (this.K) {
            return;
        }
        this.K = true;
        ActionBarOverlayLayout actionBarOverlayLayout = (ActionBarOverlayLayout) this.r;
        actionBarOverlayLayout.k();
        ActionMenuView actionMenuView = ((x1) actionBarOverlayLayout.e).a.a;
        if (actionMenuView != null && (c0095l = actionMenuView.t) != null) {
            c0095l.f();
            C0087h c0087h = c0095l.t;
            if (c0087h != null && c0087h.b()) {
                c0087h.i.dismiss();
            }
        }
        Window.Callback callback = this.l.getCallback();
        if (callback != null && !this.Y) {
            callback.onPanelClosed(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, nVar);
        }
        this.K = false;
    }

    @Override // androidx.appcompat.view.menu.l
    public final boolean r(androidx.appcompat.view.menu.n nVar, MenuItem menuItem) {
        A a;
        Window.Callback callback = this.l.getCallback();
        if (callback != null && !this.Y) {
            androidx.appcompat.view.menu.n nVarK = nVar.k();
            A[] aArr = this.L;
            int length = aArr != null ? aArr.length : 0;
            int i = 0;
            while (true) {
                if (i < length) {
                    a = aArr[i];
                    if (a != null && a.h == nVarK) {
                        break;
                    }
                    i++;
                } else {
                    a = null;
                    break;
                }
            }
            if (a != null) {
                return callback.onMenuItemSelected(a.a, menuItem);
            }
        }
        return false;
    }

    public final void s(A a, boolean z) {
        z zVar;
        InterfaceC0094k0 interfaceC0094k0;
        if (z && a.a == 0 && (interfaceC0094k0 = this.r) != null) {
            ActionBarOverlayLayout actionBarOverlayLayout = (ActionBarOverlayLayout) interfaceC0094k0;
            actionBarOverlayLayout.k();
            if (((x1) actionBarOverlayLayout.e).a.p()) {
                q(a.h);
                return;
            }
        }
        WindowManager windowManager = (WindowManager) this.k.getSystemService("window");
        if (windowManager != null && a.m && (zVar = a.e) != null) {
            windowManager.removeView(zVar);
            if (z) {
                p(a.a, a, null);
            }
        }
        a.k = false;
        a.l = false;
        a.m = false;
        a.f = null;
        a.n = true;
        if (this.M == a) {
            this.M = null;
        }
        if (a.a == 0) {
            J();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x003f  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x011b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean u(android.view.KeyEvent r7) throws java.lang.IllegalAccessException, java.lang.NoSuchMethodException, java.lang.SecurityException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 317
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.B.u(android.view.KeyEvent):boolean");
    }

    public final void v(int i) {
        A aZ = z(i);
        if (aZ.h != null) {
            Bundle bundle = new Bundle();
            aZ.h.t(bundle);
            if (bundle.size() > 0) {
                aZ.p = bundle;
            }
            aZ.h.w();
            aZ.h.clear();
        }
        aZ.o = true;
        aZ.n = true;
        if ((i == 108 || i == 0) && this.r != null) {
            A aZ2 = z(0);
            aZ2.k = false;
            H(aZ2, null);
        }
    }

    public final void w() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        ViewGroup viewGroup;
        int i = 1;
        if (this.z) {
            return;
        }
        int[] iArr = androidx.appcompat.a.j;
        Context context = this.k;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(iArr);
        if (!typedArrayObtainStyledAttributes.hasValue(117)) {
            typedArrayObtainStyledAttributes.recycle();
            throw new IllegalStateException("You need to use a Theme.AppCompat theme (or descendant) with this activity.");
        }
        if (typedArrayObtainStyledAttributes.getBoolean(126, false)) {
            g(1);
        } else if (typedArrayObtainStyledAttributes.getBoolean(117, false)) {
            g(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY);
        }
        if (typedArrayObtainStyledAttributes.getBoolean(118, false)) {
            g(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION);
        }
        if (typedArrayObtainStyledAttributes.getBoolean(119, false)) {
            g(10);
        }
        this.I = typedArrayObtainStyledAttributes.getBoolean(0, false);
        typedArrayObtainStyledAttributes.recycle();
        x();
        this.l.getDecorView();
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(context);
        if (this.J) {
            viewGroup = this.H ? (ViewGroup) layoutInflaterFrom.inflate(com.quizlet.quizletandroid.R.layout.abc_screen_simple_overlay_action_mode, (ViewGroup) null) : (ViewGroup) layoutInflaterFrom.inflate(com.quizlet.quizletandroid.R.layout.abc_screen_simple, (ViewGroup) null);
        } else if (this.I) {
            viewGroup = (ViewGroup) layoutInflaterFrom.inflate(com.quizlet.quizletandroid.R.layout.abc_dialog_title_material, (ViewGroup) null);
            this.G = false;
            this.F = false;
        } else if (this.F) {
            TypedValue typedValue = new TypedValue();
            context.getTheme().resolveAttribute(com.quizlet.quizletandroid.R.attr.actionBarTheme, typedValue, true);
            viewGroup = (ViewGroup) LayoutInflater.from(typedValue.resourceId != 0 ? new androidx.appcompat.view.d(context, typedValue.resourceId) : context).inflate(com.quizlet.quizletandroid.R.layout.abc_screen_toolbar, (ViewGroup) null);
            InterfaceC0094k0 interfaceC0094k0 = (InterfaceC0094k0) viewGroup.findViewById(com.quizlet.quizletandroid.R.id.decor_content_parent);
            this.r = interfaceC0094k0;
            interfaceC0094k0.setWindowCallback(this.l.getCallback());
            if (this.G) {
                ((ActionBarOverlayLayout) this.r).j(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION);
            }
            if (this.D) {
                ((ActionBarOverlayLayout) this.r).j(2);
            }
            if (this.E) {
                ((ActionBarOverlayLayout) this.r).j(5);
            }
        } else {
            viewGroup = null;
        }
        if (viewGroup == null) {
            StringBuilder sb = new StringBuilder("AppCompat does not support the current theme features: { windowActionBar: ");
            sb.append(this.F);
            sb.append(", windowActionBarOverlay: ");
            sb.append(this.G);
            sb.append(", android:windowIsFloating: ");
            sb.append(this.I);
            sb.append(", windowActionModeOverlay: ");
            sb.append(this.H);
            sb.append(", windowNoTitle: ");
            throw new IllegalArgumentException(android.support.v4.media.session.a.o(" }", sb, this.J));
        }
        com.airbnb.lottie.network.c cVar = new com.airbnb.lottie.network.c(this, i);
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        androidx.core.view.L.m(viewGroup, cVar);
        if (this.r == null) {
            this.B = (TextView) viewGroup.findViewById(com.quizlet.quizletandroid.R.id.title);
        }
        boolean z = C1.a;
        try {
            Method method = viewGroup.getClass().getMethod("makeOptionalFitsSystemWindows", null);
            if (!method.isAccessible()) {
                method.setAccessible(true);
            }
            method.invoke(viewGroup, null);
        } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException unused) {
        }
        ContentFrameLayout contentFrameLayout = (ContentFrameLayout) viewGroup.findViewById(com.quizlet.quizletandroid.R.id.action_bar_activity_content);
        ViewGroup viewGroup2 = (ViewGroup) this.l.findViewById(R.id.content);
        if (viewGroup2 != null) {
            while (viewGroup2.getChildCount() > 0) {
                View childAt = viewGroup2.getChildAt(0);
                viewGroup2.removeViewAt(0);
                contentFrameLayout.addView(childAt);
            }
            viewGroup2.setId(-1);
            contentFrameLayout.setId(R.id.content);
            if (viewGroup2 instanceof FrameLayout) {
                ((FrameLayout) viewGroup2).setForeground(null);
            }
        }
        this.l.setContentView(viewGroup);
        contentFrameLayout.setAttachListener(new com.airbnb.lottie.network.d(this, i));
        this.A = viewGroup;
        Object obj = this.j;
        CharSequence title = obj instanceof Activity ? ((Activity) obj).getTitle() : this.q;
        if (!TextUtils.isEmpty(title)) {
            InterfaceC0094k0 interfaceC0094k02 = this.r;
            if (interfaceC0094k02 != null) {
                interfaceC0094k02.setWindowTitle(title);
            } else {
                com.bumptech.glide.c cVar2 = this.o;
                if (cVar2 != null) {
                    cVar2.B(title);
                } else {
                    TextView textView = this.B;
                    if (textView != null) {
                        textView.setText(title);
                    }
                }
            }
        }
        ContentFrameLayout contentFrameLayout2 = (ContentFrameLayout) this.A.findViewById(R.id.content);
        View decorView = this.l.getDecorView();
        contentFrameLayout2.g.set(decorView.getPaddingLeft(), decorView.getPaddingTop(), decorView.getPaddingRight(), decorView.getPaddingBottom());
        if (contentFrameLayout2.isLaidOut()) {
            contentFrameLayout2.requestLayout();
        }
        TypedArray typedArrayObtainStyledAttributes2 = context.obtainStyledAttributes(iArr);
        typedArrayObtainStyledAttributes2.getValue(124, contentFrameLayout2.getMinWidthMajor());
        typedArrayObtainStyledAttributes2.getValue(125, contentFrameLayout2.getMinWidthMinor());
        if (typedArrayObtainStyledAttributes2.hasValue(ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND)) {
            typedArrayObtainStyledAttributes2.getValue(ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND, contentFrameLayout2.getFixedWidthMajor());
        }
        if (typedArrayObtainStyledAttributes2.hasValue(ContentType.USER_GENERATED_LIVE)) {
            typedArrayObtainStyledAttributes2.getValue(ContentType.USER_GENERATED_LIVE, contentFrameLayout2.getFixedWidthMinor());
        }
        if (typedArrayObtainStyledAttributes2.hasValue(120)) {
            typedArrayObtainStyledAttributes2.getValue(120, contentFrameLayout2.getFixedHeightMajor());
        }
        if (typedArrayObtainStyledAttributes2.hasValue(ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND)) {
            typedArrayObtainStyledAttributes2.getValue(ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND, contentFrameLayout2.getFixedHeightMinor());
        }
        typedArrayObtainStyledAttributes2.recycle();
        contentFrameLayout2.requestLayout();
        this.z = true;
        A aZ = z(0);
        if (this.Y || aZ.h != null) {
            return;
        }
        B(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY);
    }

    public final void x() {
        if (this.l == null) {
            Object obj = this.j;
            if (obj instanceof Activity) {
                n(((Activity) obj).getWindow());
            }
        }
        if (this.l == null) {
            throw new IllegalStateException("We have not been given a Window");
        }
    }

    public final y y(Context context) {
        if (this.g1 == null) {
            if (com.google.android.gms.internal.appset.e.f == null) {
                Context applicationContext = context.getApplicationContext();
                com.google.android.gms.internal.appset.e.f = new com.google.android.gms.internal.appset.e(applicationContext, (LocationManager) applicationContext.getSystemService("location"));
            }
            this.g1 = new x(this, com.google.android.gms.internal.appset.e.f);
        }
        return this.g1;
    }

    public final A z(int i) {
        A[] aArr = this.L;
        if (aArr == null || aArr.length <= i) {
            A[] aArr2 = new A[i + 1];
            if (aArr != null) {
                System.arraycopy(aArr, 0, aArr2, 0, aArr.length);
            }
            this.L = aArr2;
            aArr = aArr2;
        }
        A a = aArr[i];
        if (a != null) {
            return a;
        }
        A a2 = new A();
        a2.a = i;
        a2.n = false;
        aArr[i] = a2;
        return a2;
    }

    @Override // android.view.LayoutInflater.Factory
    public final View onCreateView(String str, Context context, AttributeSet attributeSet) {
        return onCreateView(null, str, context, attributeSet);
    }
}
