package androidx.constraintlayout.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseIntArray;
import com.appsflyer.attribution.RequestError;
import com.comscore.android.util.AndroidTcfDataLoader;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* loaded from: classes.dex */
public final class k {
    public static final SparseIntArray q0;
    public int A;
    public int B;
    public float C;
    public int D;
    public int E;
    public int F;
    public int G;
    public int H;
    public int I;
    public int J;
    public int K;
    public int L;
    public int M;
    public int N;
    public int O;
    public int P;
    public int Q;
    public int R;
    public int S;
    public int T;
    public float U;
    public float V;
    public int W;
    public int X;
    public int Y;
    public int Z;
    public boolean a;
    public int a0;
    public boolean b;
    public int b0;
    public int c;
    public int c0;
    public int d;
    public int d0;
    public int e;
    public float e0;
    public int f;
    public float f0;
    public float g;
    public int g0;
    public boolean h;
    public int h0;
    public int i;
    public int i0;
    public int j;
    public int[] j0;
    public int k;
    public String k0;
    public int l;
    public String l0;
    public int m;
    public boolean m0;
    public int n;
    public boolean n0;
    public int o;
    public boolean o0;
    public int p;
    public int p0;
    public int q;
    public int r;
    public int s;
    public int t;
    public int u;
    public int v;
    public int w;
    public float x;
    public float y;
    public String z;

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        q0 = sparseIntArray;
        sparseIntArray.append(43, 24);
        sparseIntArray.append(44, 25);
        sparseIntArray.append(46, 28);
        sparseIntArray.append(47, 29);
        sparseIntArray.append(52, 35);
        sparseIntArray.append(51, 34);
        sparseIntArray.append(24, 4);
        sparseIntArray.append(23, 3);
        sparseIntArray.append(19, 1);
        sparseIntArray.append(61, 6);
        sparseIntArray.append(62, 7);
        sparseIntArray.append(31, 17);
        sparseIntArray.append(32, 18);
        sparseIntArray.append(33, 19);
        sparseIntArray.append(15, 90);
        sparseIntArray.append(0, 26);
        sparseIntArray.append(48, 31);
        sparseIntArray.append(49, 32);
        sparseIntArray.append(30, 10);
        sparseIntArray.append(29, 9);
        sparseIntArray.append(66, 13);
        sparseIntArray.append(69, 16);
        sparseIntArray.append(67, 14);
        sparseIntArray.append(64, 11);
        sparseIntArray.append(68, 15);
        sparseIntArray.append(65, 12);
        sparseIntArray.append(55, 38);
        sparseIntArray.append(41, 37);
        sparseIntArray.append(40, 39);
        sparseIntArray.append(54, 40);
        sparseIntArray.append(39, 20);
        sparseIntArray.append(53, 36);
        sparseIntArray.append(28, 5);
        sparseIntArray.append(42, 91);
        sparseIntArray.append(50, 91);
        sparseIntArray.append(45, 91);
        sparseIntArray.append(22, 91);
        sparseIntArray.append(18, 91);
        sparseIntArray.append(3, 23);
        sparseIntArray.append(5, 27);
        sparseIntArray.append(7, 30);
        sparseIntArray.append(8, 8);
        sparseIntArray.append(4, 33);
        sparseIntArray.append(6, 2);
        sparseIntArray.append(1, 22);
        sparseIntArray.append(2, 21);
        sparseIntArray.append(56, 41);
        sparseIntArray.append(34, 42);
        sparseIntArray.append(17, 87);
        sparseIntArray.append(16, 88);
        sparseIntArray.append(71, 76);
        sparseIntArray.append(25, 61);
        sparseIntArray.append(27, 62);
        sparseIntArray.append(26, 63);
        sparseIntArray.append(60, 69);
        sparseIntArray.append(38, 70);
        sparseIntArray.append(12, 71);
        sparseIntArray.append(10, 72);
        sparseIntArray.append(11, 73);
        sparseIntArray.append(13, 74);
        sparseIntArray.append(9, 75);
        sparseIntArray.append(58, 84);
        sparseIntArray.append(59, 86);
        sparseIntArray.append(58, 83);
        sparseIntArray.append(37, 85);
        sparseIntArray.append(56, 87);
        sparseIntArray.append(34, 88);
        sparseIntArray.append(91, 89);
        sparseIntArray.append(15, 90);
    }

    public final void a(Context context, AttributeSet attributeSet) {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, u.f);
        this.b = true;
        int indexCount = typedArrayObtainStyledAttributes.getIndexCount();
        for (int i = 0; i < indexCount; i++) {
            int index = typedArrayObtainStyledAttributes.getIndex(i);
            SparseIntArray sparseIntArray = q0;
            int i2 = sparseIntArray.get(index);
            switch (i2) {
                case 1:
                    this.q = o.j(typedArrayObtainStyledAttributes, index, this.q);
                    break;
                case 2:
                    this.J = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.J);
                    break;
                case 3:
                    this.p = o.j(typedArrayObtainStyledAttributes, index, this.p);
                    break;
                case 4:
                    this.o = o.j(typedArrayObtainStyledAttributes, index, this.o);
                    break;
                case 5:
                    this.z = typedArrayObtainStyledAttributes.getString(index);
                    break;
                case 6:
                    this.D = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, this.D);
                    break;
                case 7:
                    this.E = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, this.E);
                    break;
                case 8:
                    this.K = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.K);
                    break;
                case 9:
                    this.w = o.j(typedArrayObtainStyledAttributes, index, this.w);
                    break;
                case 10:
                    this.v = o.j(typedArrayObtainStyledAttributes, index, this.v);
                    break;
                case 11:
                    this.Q = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.Q);
                    break;
                case 12:
                    this.R = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.R);
                    break;
                case 13:
                    this.N = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.N);
                    break;
                case 14:
                    this.P = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.P);
                    break;
                case 15:
                    this.S = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.S);
                    break;
                case 16:
                    this.O = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.O);
                    break;
                case 17:
                    this.e = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, this.e);
                    break;
                case 18:
                    this.f = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, this.f);
                    break;
                case 19:
                    this.g = typedArrayObtainStyledAttributes.getFloat(index, this.g);
                    break;
                case 20:
                    this.x = typedArrayObtainStyledAttributes.getFloat(index, this.x);
                    break;
                case 21:
                    this.d = typedArrayObtainStyledAttributes.getLayoutDimension(index, this.d);
                    break;
                case EventType.WINDOW_STATE /* 22 */:
                    this.c = typedArrayObtainStyledAttributes.getLayoutDimension(index, this.c);
                    break;
                case EventType.AUDIO /* 23 */:
                    this.G = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.G);
                    break;
                case EventType.VIDEO /* 24 */:
                    this.i = o.j(typedArrayObtainStyledAttributes, index, this.i);
                    break;
                case EventType.SUBS /* 25 */:
                    this.j = o.j(typedArrayObtainStyledAttributes, index, this.j);
                    break;
                case EventType.CDN /* 26 */:
                    this.F = typedArrayObtainStyledAttributes.getInt(index, this.F);
                    break;
                case 27:
                    this.H = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.H);
                    break;
                case 28:
                    this.k = o.j(typedArrayObtainStyledAttributes, index, this.k);
                    break;
                case 29:
                    this.l = o.j(typedArrayObtainStyledAttributes, index, this.l);
                    break;
                case 30:
                    this.L = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.L);
                    break;
                case 31:
                    this.t = o.j(typedArrayObtainStyledAttributes, index, this.t);
                    break;
                case 32:
                    this.u = o.j(typedArrayObtainStyledAttributes, index, this.u);
                    break;
                case 33:
                    this.I = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.I);
                    break;
                case 34:
                    this.n = o.j(typedArrayObtainStyledAttributes, index, this.n);
                    break;
                case 35:
                    this.m = o.j(typedArrayObtainStyledAttributes, index, this.m);
                    break;
                case 36:
                    this.y = typedArrayObtainStyledAttributes.getFloat(index, this.y);
                    break;
                case 37:
                    this.V = typedArrayObtainStyledAttributes.getFloat(index, this.V);
                    break;
                case 38:
                    this.U = typedArrayObtainStyledAttributes.getFloat(index, this.U);
                    break;
                case 39:
                    this.W = typedArrayObtainStyledAttributes.getInt(index, this.W);
                    break;
                case RequestError.NETWORK_FAILURE /* 40 */:
                    this.X = typedArrayObtainStyledAttributes.getInt(index, this.X);
                    break;
                case RequestError.NO_DEV_KEY /* 41 */:
                    o.k(this, typedArrayObtainStyledAttributes, index, 0);
                    break;
                case 42:
                    o.k(this, typedArrayObtainStyledAttributes, index, 1);
                    break;
                default:
                    switch (i2) {
                        case 61:
                            this.A = o.j(typedArrayObtainStyledAttributes, index, this.A);
                            break;
                        case 62:
                            this.B = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.B);
                            break;
                        case 63:
                            this.C = typedArrayObtainStyledAttributes.getFloat(index, this.C);
                            break;
                        default:
                            switch (i2) {
                                case 69:
                                    this.e0 = typedArrayObtainStyledAttributes.getFloat(index, 1.0f);
                                    break;
                                case 70:
                                    this.f0 = typedArrayObtainStyledAttributes.getFloat(index, 1.0f);
                                    break;
                                case 71:
                                    Log.e("ConstraintSet", "CURRENTLY UNSUPPORTED");
                                    break;
                                case 72:
                                    this.g0 = typedArrayObtainStyledAttributes.getInt(index, this.g0);
                                    break;
                                case 73:
                                    this.h0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.h0);
                                    break;
                                case 74:
                                    this.k0 = typedArrayObtainStyledAttributes.getString(index);
                                    break;
                                case 75:
                                    this.o0 = typedArrayObtainStyledAttributes.getBoolean(index, this.o0);
                                    break;
                                case 76:
                                    this.p0 = typedArrayObtainStyledAttributes.getInt(index, this.p0);
                                    break;
                                case AndroidTcfDataLoader.COMSCORE_VENDOR_INDEX /* 77 */:
                                    this.r = o.j(typedArrayObtainStyledAttributes, index, this.r);
                                    break;
                                case 78:
                                    this.s = o.j(typedArrayObtainStyledAttributes, index, this.s);
                                    break;
                                case 79:
                                    this.T = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.T);
                                    break;
                                case 80:
                                    this.M = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.M);
                                    break;
                                case 81:
                                    this.Y = typedArrayObtainStyledAttributes.getInt(index, this.Y);
                                    break;
                                case 82:
                                    this.Z = typedArrayObtainStyledAttributes.getInt(index, this.Z);
                                    break;
                                case 83:
                                    this.b0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.b0);
                                    break;
                                case 84:
                                    this.a0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.a0);
                                    break;
                                case 85:
                                    this.d0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.d0);
                                    break;
                                case 86:
                                    this.c0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index, this.c0);
                                    break;
                                case 87:
                                    this.m0 = typedArrayObtainStyledAttributes.getBoolean(index, this.m0);
                                    break;
                                case 88:
                                    this.n0 = typedArrayObtainStyledAttributes.getBoolean(index, this.n0);
                                    break;
                                case 89:
                                    this.l0 = typedArrayObtainStyledAttributes.getString(index);
                                    break;
                                case SubsamplingScaleImageView.ORIENTATION_90 /* 90 */:
                                    this.h = typedArrayObtainStyledAttributes.getBoolean(index, this.h);
                                    break;
                                case 91:
                                    Log.w("ConstraintSet", "unused attribute 0x" + Integer.toHexString(index) + "   " + sparseIntArray.get(index));
                                    break;
                                default:
                                    Log.w("ConstraintSet", "Unknown attribute 0x" + Integer.toHexString(index) + "   " + sparseIntArray.get(index));
                                    break;
                            }
                    }
            }
        }
        typedArrayObtainStyledAttributes.recycle();
    }
}
