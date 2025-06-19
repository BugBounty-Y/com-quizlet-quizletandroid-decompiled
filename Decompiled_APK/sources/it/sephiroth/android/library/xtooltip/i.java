package it.sephiroth.android.library.xtooltip;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.os.Handler;
import android.util.LruCache;
import android.view.View;
import android.view.ViewPropertyAnimator;
import android.view.WindowManager;
import android.widget.TextView;
import androidx.compose.animation.d0;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.ads.G;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import kotlin.TypeCastException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public j A;
    public final m B;
    public final WeakReference C;
    public View D;
    public TextView E;
    public final h F;
    public final h G;
    public G H;
    public f I;
    public int[] J;
    public final int[] K;
    public final Context L;
    public final WindowManager a;
    public boolean b;
    public final ArrayList c;
    public boolean d;
    public final float e;
    public final boolean f;
    public final int g;
    public final int h;
    public final Handler i;
    public g j;
    public final String k;
    public final Point l;
    public final boolean m;
    public final int n;
    public final a o;
    public final long p;
    public final int q;
    public final int r;
    public final float s;
    public final Typeface t;
    public final int u;
    public final int v;
    public final boolean w;
    public final int x;
    public boolean y;
    public final boolean z;

    public i(Context context, d dVar) {
        this.L = context;
        Object systemService = context.getSystemService("window");
        if (systemService == null) {
            throw new TypeCastException("null cannot be cast to non-null type android.view.WindowManager");
        }
        this.a = (WindowManager) systemService;
        e[] eVarArrValues = e.values();
        ArrayList arrayList = new ArrayList();
        for (e eVar : eVarArrValues) {
            if (eVar != e.e) {
                arrayList.add(eVar);
            }
        }
        this.c = arrayList;
        Resources resources = this.L.getResources();
        Intrinsics.c(resources, "context.resources");
        this.e = resources.getDisplayMetrics().density * 10;
        this.f = true;
        this.g = 1000;
        this.h = 2;
        this.i = new Handler();
        this.u = R.layout.textview;
        this.v = android.R.id.text1;
        this.F = new h(this, 1);
        this.G = new h(this, 0);
        new androidx.coordinatorlayout.widget.f(this, 3);
        Typeface typeface = null;
        TypedArray typedArrayObtainStyledAttributes = this.L.getTheme().obtainStyledAttributes(null, b.a, dVar.f, dVar.e);
        this.n = typedArrayObtainStyledAttributes.getDimensionPixelSize(8, 30);
        this.q = typedArrayObtainStyledAttributes.getResourceId(0, 0);
        this.r = typedArrayObtainStyledAttributes.getInt(1, 8388659);
        this.s = typedArrayObtainStyledAttributes.getDimension(5, DefinitionKt.NO_Float_VALUE);
        this.x = typedArrayObtainStyledAttributes.getResourceId(7, R.style.ToolTipOverlayDefaultStyle);
        String string = typedArrayObtainStyledAttributes.getString(6);
        typedArrayObtainStyledAttributes.recycle();
        this.k = dVar.c;
        Point point = dVar.a;
        if (point == null) {
            Intrinsics.l();
        }
        this.l = point;
        this.o = dVar.b;
        this.p = 100L;
        this.w = dVar.h;
        this.m = true;
        View view = dVar.d;
        if (view != null) {
            this.C = new WeakReference(view);
            this.z = true;
        }
        this.B = new m(this.L, dVar);
        Typeface typeface2 = dVar.g;
        if (typeface2 != null) {
            this.t = typeface2;
        } else if (string != null) {
            LruCache lruCache = n.a;
            Context context2 = this.L;
            LruCache lruCache2 = n.a;
            synchronized (lruCache2) {
                Typeface typeface3 = (Typeface) lruCache2.get(string);
                if (typeface3 == null) {
                    try {
                        Typeface typefaceCreateFromAsset = Typeface.createFromAsset(context2.getAssets(), string);
                        lruCache2.put(string, typefaceCreateFromAsset);
                        typeface = typefaceCreateFromAsset;
                    } catch (Exception e) {
                        timber.log.c.a.d("Could not get typeface '" + string + "' because " + e.getMessage(), new Object[0]);
                    }
                } else {
                    typeface = typeface3;
                }
            }
            this.t = typeface;
        }
        this.K = new int[]{0, 0};
    }

    public final void a() {
        if (!this.b || this.j == null) {
            return;
        }
        WeakReference weakReference = this.C;
        if (weakReference != null) {
        }
        Handler handler = this.i;
        handler.removeCallbacks(this.F);
        handler.removeCallbacks(this.G);
        this.a.removeView(this.j);
        timber.log.c.a.m("dismiss: " + this.j, new Object[0]);
        this.j = null;
        this.b = false;
        this.d = false;
        G g = this.H;
        if (g != null) {
            g.invoke(this);
        }
    }

    public final f b(View view, View view2, Point point, ArrayList arrayList, WindowManager.LayoutParams layoutParams) throws Throwable {
        Throwable th;
        j jVar;
        if (this.j == null || arrayList.isEmpty()) {
            return null;
        }
        Object objRemove = arrayList.remove(0);
        Intrinsics.c(objRemove, "gravities.removeAt(0)");
        e eVar = (e) objRemove;
        timber.log.a aVar = timber.log.c.a;
        aVar.g("findPosition. " + eVar + ", offset: " + point, new Object[0]);
        Rect rect = new Rect();
        int[] iArr = {0, 0};
        Point point2 = new Point(point);
        view.getWindowVisibleDisplayFrame(rect);
        if (view2 != null) {
            view2.getLocationOnScreen(iArr);
            th = null;
            point2.x = (view2.getWidth() / 2) + iArr[0] + point2.x;
            point2.y = (view2.getHeight() / 2) + iArr[1] + point2.y;
            int iOrdinal = eVar.ordinal();
            if (iOrdinal == 0) {
                iArr[1] = (view2.getHeight() / 2) + iArr[1];
            } else if (iOrdinal == 1) {
                iArr[0] = view2.getWidth() + iArr[0];
                iArr[1] = (view2.getHeight() / 2) + iArr[1];
            } else if (iOrdinal == 2) {
                iArr[0] = (view2.getWidth() / 2) + iArr[0];
            } else if (iOrdinal == 3) {
                iArr[0] = (view2.getWidth() / 2) + iArr[0];
                iArr[1] = view2.getHeight() + iArr[1];
            } else if (iOrdinal == 4) {
                iArr[0] = (view2.getWidth() / 2) + iArr[0];
                iArr[1] = (view2.getHeight() / 2) + iArr[1];
            }
        } else {
            th = null;
        }
        iArr[0] = iArr[0] + point.x;
        iArr[1] = iArr[1] + point.y;
        aVar.a("anchorPosition: " + iArr[0] + ", " + iArr[1], new Object[0]);
        StringBuilder sb = new StringBuilder("centerPosition: ");
        sb.append(point2);
        aVar.a(sb.toString(), new Object[0]);
        aVar.a("displayFrame: " + rect, new Object[0]);
        View view3 = this.D;
        if (view3 == null) {
            Intrinsics.m("mContentView");
            throw th;
        }
        int measuredWidth = view3.getMeasuredWidth();
        View view4 = this.D;
        if (view4 == null) {
            Intrinsics.m("mContentView");
            throw th;
        }
        int measuredHeight = view4.getMeasuredHeight();
        aVar.m(d0.p("contentView size: ", measuredWidth, ", ", measuredHeight), new Object[0]);
        Point point3 = new Point();
        Point point4 = new Point();
        int iOrdinal2 = eVar.ordinal();
        int i = this.n;
        if (iOrdinal2 == 0) {
            point3.x = iArr[0] - measuredWidth;
            int i2 = measuredHeight / 2;
            point3.y = iArr[1] - i2;
            point4.y = i2 - (i / 2);
        } else if (iOrdinal2 == 1) {
            point3.x = iArr[0];
            int i3 = measuredHeight / 2;
            point3.y = iArr[1] - i3;
            point4.y = i3 - (i / 2);
        } else if (iOrdinal2 == 2) {
            int i4 = measuredWidth / 2;
            point3.x = iArr[0] - i4;
            point3.y = iArr[1] - measuredHeight;
            point4.x = i4 - (i / 2);
        } else if (iOrdinal2 == 3) {
            int i5 = measuredWidth / 2;
            point3.x = iArr[0] - i5;
            point3.y = iArr[1];
            point4.x = i5 - (i / 2);
        } else if (iOrdinal2 == 4) {
            point3.x = iArr[0] - (measuredWidth / 2);
            point3.y = iArr[1] - (measuredHeight / 2);
        }
        if (view2 == null && (jVar = this.A) != null) {
            int iOrdinal3 = eVar.ordinal();
            if (iOrdinal3 == 0) {
                point3.x -= jVar.getMeasuredWidth() / 2;
            } else if (iOrdinal3 == 1) {
                point3.x = (jVar.getMeasuredWidth() / 2) + point3.x;
            } else if (iOrdinal3 == 2) {
                point3.y -= jVar.getMeasuredHeight() / 2;
            } else if (iOrdinal3 == 3) {
                point3.y = (jVar.getMeasuredHeight() / 2) + point3.y;
            }
        }
        aVar.a("arrowPosition: " + point4, new Object[0]);
        aVar.a("centerPosition: " + point2, new Object[0]);
        aVar.a("contentPosition: " + point3, new Object[0]);
        int i6 = point3.x;
        int i7 = point3.y;
        Rect rect2 = new Rect(i6, i7, measuredWidth + i6, measuredHeight + i7);
        int i8 = (int) this.e;
        if (rect.contains(rect2.left + i8, rect2.top + i8, rect2.right - i8, rect2.bottom - i8)) {
            return new f(rect, point4, point2, point3, eVar, layoutParams);
        }
        aVar.d("content won't fit! " + rect + ", " + rect2, new Object[0]);
        return b(view, view2, point, arrayList, layoutParams);
    }

    public final void c() {
        timber.log.a aVar = timber.log.c.a;
        aVar.g("hide", new Object[0]);
        boolean z = this.b;
        if (z && z && this.d) {
            this.d = false;
            Handler handler = this.i;
            handler.removeCallbacks(this.F);
            handler.removeCallbacks(this.G);
            StringBuilder sb = new StringBuilder("fadeOut(");
            long j = this.p;
            aVar.g(d0.q(sb, j, ')'), new Object[0]);
            if (j <= 0) {
                a();
                return;
            }
            g gVar = this.j;
            if (gVar != null) {
                gVar.clearAnimation();
                ViewPropertyAnimator duration = gVar.animate().alpha(DefinitionKt.NO_Float_VALUE).setDuration(j);
                Intrinsics.c(duration, "popupView.animate()\n    …setDuration(fadeDuration)");
                com.perimeterx.mobile_sdk.doctor_app.ui.n nVar = new com.perimeterx.mobile_sdk.doctor_app.ui.n();
                nVar.b = new androidx.compose.ui.viewinterop.b(28, gVar, this);
                duration.setListener(nVar);
                duration.start();
            }
        }
    }

    public final void d(int i, int i2) {
        if (!this.b || this.j == null || this.I == null) {
            return;
        }
        timber.log.c.a.g("offsetBy(" + i + ", " + i2 + ')', new Object[0]);
        View view = this.D;
        if (view == null) {
            Intrinsics.m("mContentView");
            throw null;
        }
        if (this.I == null) {
            Intrinsics.l();
        }
        float f = i;
        view.setTranslationX(r3.e + f);
        View view2 = this.D;
        if (view2 == null) {
            Intrinsics.m("mContentView");
            throw null;
        }
        if (this.I == null) {
            Intrinsics.l();
        }
        float f2 = i2;
        view2.setTranslationY(r1.f + f2);
        j jVar = this.A;
        if (jVar != null) {
            if (this.I == null) {
                Intrinsics.l();
            }
            jVar.setTranslationX((r1.a - (jVar.getMeasuredWidth() / 2)) + f);
            if (this.I == null) {
                Intrinsics.l();
            }
            jVar.setTranslationY((r5.b - (jVar.getMeasuredHeight() / 2)) + f2);
        }
    }
}
