package androidx.vectordrawable.graphics.drawable;

import android.graphics.Matrix;
import android.graphics.Paint;
import androidx.collection.C0208f;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class j extends k {
    public final Matrix a;
    public final ArrayList b;
    public float c;
    public float d;
    public float e;
    public float f;
    public float g;
    public float h;
    public float i;
    public final Matrix j;
    public String k;

    public j() {
        this.a = new Matrix();
        this.b = new ArrayList();
        this.c = DefinitionKt.NO_Float_VALUE;
        this.d = DefinitionKt.NO_Float_VALUE;
        this.e = DefinitionKt.NO_Float_VALUE;
        this.f = 1.0f;
        this.g = 1.0f;
        this.h = DefinitionKt.NO_Float_VALUE;
        this.i = DefinitionKt.NO_Float_VALUE;
        this.j = new Matrix();
        this.k = null;
    }

    @Override // androidx.vectordrawable.graphics.drawable.k
    public final boolean a() {
        int i = 0;
        while (true) {
            ArrayList arrayList = this.b;
            if (i >= arrayList.size()) {
                return false;
            }
            if (((k) arrayList.get(i)).a()) {
                return true;
            }
            i++;
        }
    }

    @Override // androidx.vectordrawable.graphics.drawable.k
    public final boolean b(int[] iArr) {
        int i = 0;
        boolean zB = false;
        while (true) {
            ArrayList arrayList = this.b;
            if (i >= arrayList.size()) {
                return zB;
            }
            zB |= ((k) arrayList.get(i)).b(iArr);
            i++;
        }
    }

    public final void c() {
        Matrix matrix = this.j;
        matrix.reset();
        matrix.postTranslate(-this.d, -this.e);
        matrix.postScale(this.f, this.g);
        matrix.postRotate(this.c, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
        matrix.postTranslate(this.h + this.d, this.i + this.e);
    }

    public String getGroupName() {
        return this.k;
    }

    public Matrix getLocalMatrix() {
        return this.j;
    }

    public float getPivotX() {
        return this.d;
    }

    public float getPivotY() {
        return this.e;
    }

    public float getRotation() {
        return this.c;
    }

    public float getScaleX() {
        return this.f;
    }

    public float getScaleY() {
        return this.g;
    }

    public float getTranslateX() {
        return this.h;
    }

    public float getTranslateY() {
        return this.i;
    }

    public void setPivotX(float f) {
        if (f != this.d) {
            this.d = f;
            c();
        }
    }

    public void setPivotY(float f) {
        if (f != this.e) {
            this.e = f;
            c();
        }
    }

    public void setRotation(float f) {
        if (f != this.c) {
            this.c = f;
            c();
        }
    }

    public void setScaleX(float f) {
        if (f != this.f) {
            this.f = f;
            c();
        }
    }

    public void setScaleY(float f) {
        if (f != this.g) {
            this.g = f;
            c();
        }
    }

    public void setTranslateX(float f) {
        if (f != this.h) {
            this.h = f;
            c();
        }
    }

    public void setTranslateY(float f) {
        if (f != this.i) {
            this.i = f;
            c();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public j(j jVar, C0208f c0208f) {
        h hVar;
        this.a = new Matrix();
        this.b = new ArrayList();
        this.c = DefinitionKt.NO_Float_VALUE;
        this.d = DefinitionKt.NO_Float_VALUE;
        this.e = DefinitionKt.NO_Float_VALUE;
        this.f = 1.0f;
        this.g = 1.0f;
        this.h = DefinitionKt.NO_Float_VALUE;
        this.i = DefinitionKt.NO_Float_VALUE;
        Matrix matrix = new Matrix();
        this.j = matrix;
        this.k = null;
        this.c = jVar.c;
        this.d = jVar.d;
        this.e = jVar.e;
        this.f = jVar.f;
        this.g = jVar.g;
        this.h = jVar.h;
        this.i = jVar.i;
        String str = jVar.k;
        this.k = str;
        if (str != null) {
            c0208f.put(str, this);
        }
        matrix.set(jVar.j);
        ArrayList arrayList = jVar.b;
        for (int i = 0; i < arrayList.size(); i++) {
            Object obj = arrayList.get(i);
            if (obj instanceof j) {
                this.b.add(new j((j) obj, c0208f));
            } else {
                if (obj instanceof i) {
                    i iVar = (i) obj;
                    i iVar2 = new i(iVar);
                    iVar2.e = DefinitionKt.NO_Float_VALUE;
                    iVar2.g = 1.0f;
                    iVar2.h = 1.0f;
                    iVar2.i = DefinitionKt.NO_Float_VALUE;
                    iVar2.j = 1.0f;
                    iVar2.k = DefinitionKt.NO_Float_VALUE;
                    iVar2.l = Paint.Cap.BUTT;
                    iVar2.m = Paint.Join.MITER;
                    iVar2.n = 4.0f;
                    iVar2.d = iVar.d;
                    iVar2.e = iVar.e;
                    iVar2.g = iVar.g;
                    iVar2.f = iVar.f;
                    iVar2.c = iVar.c;
                    iVar2.h = iVar.h;
                    iVar2.i = iVar.i;
                    iVar2.j = iVar.j;
                    iVar2.k = iVar.k;
                    iVar2.l = iVar.l;
                    iVar2.m = iVar.m;
                    iVar2.n = iVar.n;
                    hVar = iVar2;
                } else if (obj instanceof h) {
                    hVar = new h((h) obj);
                } else {
                    throw new IllegalStateException("Unknown object in the tree!");
                }
                this.b.add(hVar);
                Object obj2 = hVar.b;
                if (obj2 != null) {
                    c0208f.put(obj2, hVar);
                }
            }
        }
    }
}
