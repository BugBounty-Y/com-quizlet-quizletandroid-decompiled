package com.google.android.gms.internal.mlkit_vision_barcode;

import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.C0386g;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.EssayInfo;
import com.quizlet.quizletandroid.R;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.charset.Charset;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class Z6 {
    public static final void a(EssayInfo artifact, String str, androidx.compose.ui.q qVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(artifact, "artifact");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1193822806);
        int i2 = i | (c0814p.h(artifact) ? 4 : 2) | (c0814p.f(str) ? 32 : 16) | (c0814p.f(qVar) ? 256 : 128) | (c0814p.h(function1) ? 2048 : 1024);
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.g gVar = androidx.compose.ui.b.n;
            C0386g c0386g = AbstractC0398m.e;
            com.quizlet.themes.m.g.s();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(AbstractC0382e.u(qVar, com.quizlet.ui.resources.designsystem.generated.j.h).g(androidx.compose.foundation.layout.K0.c), "ArtifactErrorContent");
            androidx.compose.foundation.layout.B bA = androidx.compose.foundation.layout.A.a(c0386g, gVar, c0814p, 54);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            c0814p.X(-551446099);
            com.quizlet.features.notes.data.a aVar = artifact != null ? new com.quizlet.features.notes.data.a(com.quizlet.themes.e.a(c0814p).b.h(c0814p)) : null;
            c0814p.p(false);
            c0814p.X(825930087);
            if (aVar != null) {
                c0814p.X(825931781);
                String strD = str == null ? AbstractC3106b5.d(c0814p, R.string.your_magic_notes) : str;
                c0814p.p(false);
                AbstractC3099a7.a(strD, aVar.a, null, false, c0814p, 0, 24);
            }
            c0814p.p(false);
            EnumC4175w enumC4175w = artifact.b;
            c0814p.X(825940028);
            boolean zH = ((i2 & 7168) == 2048) | c0814p.h(artifact);
            Object objI = c0814p.I();
            if (zH || objI == v) {
                objI = new com.quizlet.features.notes.detail.composables.common.a(function1, artifact);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            Y6.a(enumC4175w, null, (Function0) objI, c0814p, 0);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.features.flashcards.creatormarketing.i(artifact, str, qVar, function1, i, 15);
        }
    }

    public static final Charset b(io.ktor.client.statement.b bVar) {
        io.ktor.http.d dVarB;
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        Intrinsics.checkNotNullParameter(bVar, "<this>");
        io.ktor.http.k kVarA = bVar.a();
        List list = io.ktor.http.n.a;
        String strD = kVarA.d("Content-Type");
        if (strD != null) {
            io.ktor.http.d dVar = io.ktor.http.d.f;
            dVarB = W6.b(strD);
        } else {
            dVarB = null;
        }
        if (dVarB != null) {
            return X6.b(dVarB);
        }
        return null;
    }

    public static final io.ktor.http.d c(io.ktor.client.request.c cVar) {
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        io.ktor.http.l lVar = cVar.c;
        List list = io.ktor.http.n.a;
        String strQ = lVar.q("Content-Type");
        if (strQ == null) {
            return null;
        }
        io.ktor.http.d dVar = io.ktor.http.d.f;
        return W6.b(strQ);
    }

    public static androidx.emoji2.text.flatbuffer.b d(MappedByteBuffer mappedByteBuffer) throws IOException {
        long j;
        ByteBuffer byteBufferDuplicate = mappedByteBuffer.duplicate();
        byteBufferDuplicate.order(ByteOrder.BIG_ENDIAN);
        byteBufferDuplicate.position(byteBufferDuplicate.position() + 4);
        int i = byteBufferDuplicate.getShort() & 65535;
        if (i > 100) {
            throw new IOException("Cannot read metadata.");
        }
        byteBufferDuplicate.position(byteBufferDuplicate.position() + 6);
        int i2 = 0;
        while (true) {
            if (i2 >= i) {
                j = -1;
                break;
            }
            int i3 = byteBufferDuplicate.getInt();
            byteBufferDuplicate.position(byteBufferDuplicate.position() + 4);
            j = byteBufferDuplicate.getInt() & 4294967295L;
            byteBufferDuplicate.position(byteBufferDuplicate.position() + 4);
            if (1835365473 == i3) {
                break;
            }
            i2++;
        }
        if (j != -1) {
            byteBufferDuplicate.position(byteBufferDuplicate.position() + ((int) (j - byteBufferDuplicate.position())));
            byteBufferDuplicate.position(byteBufferDuplicate.position() + 12);
            long j2 = byteBufferDuplicate.getInt() & 4294967295L;
            for (int i4 = 0; i4 < j2; i4++) {
                int i5 = byteBufferDuplicate.getInt();
                long j3 = byteBufferDuplicate.getInt() & 4294967295L;
                byteBufferDuplicate.getInt();
                if (1164798569 == i5 || 1701669481 == i5) {
                    byteBufferDuplicate.position((int) (j3 + j));
                    androidx.emoji2.text.flatbuffer.b bVar = new androidx.emoji2.text.flatbuffer.b();
                    byteBufferDuplicate.order(ByteOrder.LITTLE_ENDIAN);
                    int iPosition = byteBufferDuplicate.position() + byteBufferDuplicate.getInt(byteBufferDuplicate.position());
                    bVar.d = byteBufferDuplicate;
                    bVar.a = iPosition;
                    int i6 = iPosition - byteBufferDuplicate.getInt(iPosition);
                    bVar.b = i6;
                    bVar.c = ((ByteBuffer) bVar.d).getShort(i6);
                    return bVar;
                }
            }
        }
        throw new IOException("Cannot read metadata.");
    }
}
