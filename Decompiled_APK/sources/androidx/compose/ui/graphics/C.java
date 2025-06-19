package androidx.compose.ui.graphics;

import android.graphics.ColorSpace;
import java.util.function.DoubleUnaryOperator;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class C {
    @NotNull
    public static final ColorSpace a(@NotNull androidx.compose.ui.graphics.colorspace.c cVar) {
        ColorSpace.Rgb.TransferParameters transferParameters;
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.c)) {
            return ColorSpace.get(ColorSpace.Named.SRGB);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.o)) {
            return ColorSpace.get(ColorSpace.Named.ACES);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.p)) {
            return ColorSpace.get(ColorSpace.Named.ACESCG);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.m)) {
            return ColorSpace.get(ColorSpace.Named.ADOBE_RGB);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.h)) {
            return ColorSpace.get(ColorSpace.Named.BT2020);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.g)) {
            return ColorSpace.get(ColorSpace.Named.BT709);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.r)) {
            return ColorSpace.get(ColorSpace.Named.CIE_LAB);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.q)) {
            return ColorSpace.get(ColorSpace.Named.CIE_XYZ);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.i)) {
            return ColorSpace.get(ColorSpace.Named.DCI_P3);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.j)) {
            return ColorSpace.get(ColorSpace.Named.DISPLAY_P3);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.e)) {
            return ColorSpace.get(ColorSpace.Named.EXTENDED_SRGB);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.f)) {
            return ColorSpace.get(ColorSpace.Named.LINEAR_EXTENDED_SRGB);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.d)) {
            return ColorSpace.get(ColorSpace.Named.LINEAR_SRGB);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.k)) {
            return ColorSpace.get(ColorSpace.Named.NTSC_1953);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.n)) {
            return ColorSpace.get(ColorSpace.Named.PRO_PHOTO_RGB);
        }
        if (Intrinsics.b(cVar, androidx.compose.ui.graphics.colorspace.d.l)) {
            return ColorSpace.get(ColorSpace.Named.SMPTE_C);
        }
        if (!(cVar instanceof androidx.compose.ui.graphics.colorspace.q)) {
            return ColorSpace.get(ColorSpace.Named.SRGB);
        }
        androidx.compose.ui.graphics.colorspace.q qVar = (androidx.compose.ui.graphics.colorspace.q) cVar;
        float[] fArrA = qVar.d.a();
        androidx.compose.ui.graphics.colorspace.r rVar = qVar.g;
        if (rVar != null) {
            transferParameters = new ColorSpace.Rgb.TransferParameters(rVar.b, rVar.c, rVar.d, rVar.e, rVar.f, rVar.g, rVar.a);
        } else {
            transferParameters = null;
        }
        if (transferParameters != null) {
            return new ColorSpace.Rgb(cVar.a, qVar.h, fArrA, transferParameters);
        }
        String str = cVar.a;
        final androidx.compose.ui.graphics.colorspace.p pVar = qVar.l;
        final int i = 0;
        DoubleUnaryOperator doubleUnaryOperator = new DoubleUnaryOperator() { // from class: androidx.compose.ui.graphics.A
            @Override // java.util.function.DoubleUnaryOperator
            public final double applyAsDouble(double d) {
                switch (i) {
                    case 0:
                        return ((Number) ((androidx.compose.ui.graphics.colorspace.p) pVar).invoke(Double.valueOf(d))).doubleValue();
                    default:
                        return ((Number) ((androidx.compose.ui.graphics.colorspace.p) pVar).invoke(Double.valueOf(d))).doubleValue();
                }
            }
        };
        final androidx.compose.ui.graphics.colorspace.p pVar2 = qVar.o;
        final int i2 = 1;
        androidx.compose.ui.graphics.colorspace.q qVar2 = (androidx.compose.ui.graphics.colorspace.q) cVar;
        return new ColorSpace.Rgb(str, qVar.h, fArrA, doubleUnaryOperator, new DoubleUnaryOperator() { // from class: androidx.compose.ui.graphics.A
            @Override // java.util.function.DoubleUnaryOperator
            public final double applyAsDouble(double d) {
                switch (i2) {
                    case 0:
                        return ((Number) ((androidx.compose.ui.graphics.colorspace.p) pVar2).invoke(Double.valueOf(d))).doubleValue();
                    default:
                        return ((Number) ((androidx.compose.ui.graphics.colorspace.p) pVar2).invoke(Double.valueOf(d))).doubleValue();
                }
            }
        }, qVar2.e, qVar2.f);
    }

    @NotNull
    public static final androidx.compose.ui.graphics.colorspace.c b(@NotNull final ColorSpace colorSpace) {
        androidx.compose.ui.graphics.colorspace.s sVar;
        int id = colorSpace.getId();
        if (id == ColorSpace.Named.SRGB.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.c;
        }
        if (id == ColorSpace.Named.ACES.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.o;
        }
        if (id == ColorSpace.Named.ACESCG.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.p;
        }
        if (id == ColorSpace.Named.ADOBE_RGB.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.m;
        }
        if (id == ColorSpace.Named.BT2020.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.h;
        }
        if (id == ColorSpace.Named.BT709.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.g;
        }
        if (id == ColorSpace.Named.CIE_LAB.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.r;
        }
        if (id == ColorSpace.Named.CIE_XYZ.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.q;
        }
        if (id == ColorSpace.Named.DCI_P3.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.i;
        }
        if (id == ColorSpace.Named.DISPLAY_P3.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.j;
        }
        if (id == ColorSpace.Named.EXTENDED_SRGB.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.e;
        }
        if (id == ColorSpace.Named.LINEAR_EXTENDED_SRGB.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.f;
        }
        if (id == ColorSpace.Named.LINEAR_SRGB.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.d;
        }
        if (id == ColorSpace.Named.NTSC_1953.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.k;
        }
        if (id == ColorSpace.Named.PRO_PHOTO_RGB.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.n;
        }
        if (id == ColorSpace.Named.SMPTE_C.ordinal()) {
            return androidx.compose.ui.graphics.colorspace.d.l;
        }
        if (!(colorSpace instanceof ColorSpace.Rgb)) {
            return androidx.compose.ui.graphics.colorspace.d.c;
        }
        ColorSpace.Rgb rgb = (ColorSpace.Rgb) colorSpace;
        ColorSpace.Rgb.TransferParameters transferParameters = rgb.getTransferParameters();
        if (rgb.getWhitePoint().length == 3) {
            float f = rgb.getWhitePoint()[0];
            float f2 = rgb.getWhitePoint()[1];
            float f3 = f + f2 + rgb.getWhitePoint()[2];
            sVar = new androidx.compose.ui.graphics.colorspace.s(f / f3, f2 / f3);
        } else {
            sVar = new androidx.compose.ui.graphics.colorspace.s(rgb.getWhitePoint()[0], rgb.getWhitePoint()[1]);
        }
        androidx.compose.ui.graphics.colorspace.s sVar2 = sVar;
        androidx.compose.ui.graphics.colorspace.r rVar = transferParameters != null ? new androidx.compose.ui.graphics.colorspace.r(transferParameters.g, transferParameters.a, transferParameters.b, transferParameters.c, transferParameters.d, transferParameters.e, transferParameters.f) : null;
        String name = rgb.getName();
        float[] primaries = rgb.getPrimaries();
        float[] transform = rgb.getTransform();
        final int i = 0;
        androidx.compose.ui.graphics.colorspace.i iVar = new androidx.compose.ui.graphics.colorspace.i() { // from class: androidx.compose.ui.graphics.B
            @Override // androidx.compose.ui.graphics.colorspace.i
            public final double d(double d) {
                switch (i) {
                    case 0:
                        return ((ColorSpace.Rgb) colorSpace).getOetf().applyAsDouble(d);
                    default:
                        return ((ColorSpace.Rgb) colorSpace).getEotf().applyAsDouble(d);
                }
            }
        };
        final int i2 = 1;
        return new androidx.compose.ui.graphics.colorspace.q(name, primaries, sVar2, transform, iVar, new androidx.compose.ui.graphics.colorspace.i() { // from class: androidx.compose.ui.graphics.B
            @Override // androidx.compose.ui.graphics.colorspace.i
            public final double d(double d) {
                switch (i2) {
                    case 0:
                        return ((ColorSpace.Rgb) colorSpace).getOetf().applyAsDouble(d);
                    default:
                        return ((ColorSpace.Rgb) colorSpace).getEotf().applyAsDouble(d);
                }
            }
        }, colorSpace.getMinValue(0), colorSpace.getMaxValue(0), rVar, rgb.getId());
    }
}
