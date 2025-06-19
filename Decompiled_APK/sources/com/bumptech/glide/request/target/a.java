package com.bumptech.glide.request.target;

import android.graphics.Bitmap;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.widget.ImageView;
import com.bumptech.glide.request.g;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class a implements e {
    public final ImageView a;
    public final f b;
    public Animatable c;
    public final /* synthetic */ int d;

    public a(ImageView imageView, int i) {
        this.d = i;
        com.bumptech.glide.util.f.c(imageView, "Argument must not be null");
        this.a = imageView;
        this.b = new f(imageView);
    }

    @Override // com.bumptech.glide.request.target.e
    public final void a(Object obj) {
        i(obj);
        if (!(obj instanceof Animatable)) {
            this.c = null;
            return;
        }
        Animatable animatable = (Animatable) obj;
        this.c = animatable;
        animatable.start();
    }

    @Override // com.bumptech.glide.request.target.e
    public final com.bumptech.glide.request.c b() {
        Object tag = this.a.getTag(R.id.glide_custom_view_target_tag);
        if (tag == null) {
            return null;
        }
        if (tag instanceof com.bumptech.glide.request.c) {
            return (com.bumptech.glide.request.c) tag;
        }
        throw new IllegalArgumentException("You must not call setTag() on a view Glide is targeting");
    }

    @Override // com.bumptech.glide.request.target.e
    public final void c(g gVar) {
        this.b.b.remove(gVar);
    }

    @Override // com.bumptech.glide.request.target.e
    public final void d(com.bumptech.glide.request.c cVar) {
        this.a.setTag(R.id.glide_custom_view_target_tag, cVar);
    }

    @Override // com.bumptech.glide.request.target.e
    public final void e(g gVar) throws Throwable {
        f fVar = this.b;
        ImageView imageView = fVar.a;
        int paddingRight = imageView.getPaddingRight() + imageView.getPaddingLeft();
        ViewGroup.LayoutParams layoutParams = imageView.getLayoutParams();
        int iA = fVar.a(imageView.getWidth(), layoutParams != null ? layoutParams.width : 0, paddingRight);
        ImageView imageView2 = fVar.a;
        int paddingBottom = imageView2.getPaddingBottom() + imageView2.getPaddingTop();
        ViewGroup.LayoutParams layoutParams2 = imageView2.getLayoutParams();
        int iA2 = fVar.a(imageView2.getHeight(), layoutParams2 != null ? layoutParams2.height : 0, paddingBottom);
        if ((iA > 0 || iA == Integer.MIN_VALUE) && (iA2 > 0 || iA2 == Integer.MIN_VALUE)) {
            gVar.k(iA, iA2);
            return;
        }
        ArrayList arrayList = fVar.b;
        if (!arrayList.contains(gVar)) {
            arrayList.add(gVar);
        }
        if (fVar.c == null) {
            ViewTreeObserver viewTreeObserver = imageView2.getViewTreeObserver();
            androidx.coordinatorlayout.widget.f fVar2 = new androidx.coordinatorlayout.widget.f(fVar);
            fVar.c = fVar2;
            viewTreeObserver.addOnPreDrawListener(fVar2);
        }
    }

    @Override // com.bumptech.glide.request.target.e
    public final void f(Drawable drawable) {
        i(null);
        this.c = null;
        this.a.setImageDrawable(drawable);
    }

    @Override // com.bumptech.glide.request.target.e
    public final void g(Drawable drawable) {
        i(null);
        this.c = null;
        this.a.setImageDrawable(drawable);
    }

    @Override // com.bumptech.glide.request.target.e
    public final void h(Drawable drawable) {
        f fVar = this.b;
        ViewTreeObserver viewTreeObserver = fVar.a.getViewTreeObserver();
        if (viewTreeObserver.isAlive()) {
            viewTreeObserver.removeOnPreDrawListener(fVar.c);
        }
        fVar.c = null;
        fVar.b.clear();
        Animatable animatable = this.c;
        if (animatable != null) {
            animatable.stop();
        }
        i(null);
        this.c = null;
        this.a.setImageDrawable(drawable);
    }

    public final void i(Object obj) {
        switch (this.d) {
            case 0:
                this.a.setImageBitmap((Bitmap) obj);
                break;
            default:
                this.a.setImageDrawable((Drawable) obj);
                break;
        }
    }

    @Override // com.bumptech.glide.manager.i
    public final void onDestroy() {
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStart() {
        Animatable animatable = this.c;
        if (animatable != null) {
            animatable.start();
        }
    }

    @Override // com.bumptech.glide.manager.i
    public final void onStop() {
        Animatable animatable = this.c;
        if (animatable != null) {
            animatable.stop();
        }
    }

    public final String toString() {
        return "Target for: " + this.a;
    }
}
