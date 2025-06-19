package com.google.zxing.datamatrix.encoder;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3723t;

/* loaded from: classes2.dex */
public final class g extends com.quizlet.shared.usecase.studiableMetadata.a {
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(int i) {
        super(20);
        this.b = i;
    }

    @Override // com.quizlet.shared.usecase.studiableMetadata.a, com.google.zxing.datamatrix.encoder.b
    public void c(c cVar) {
        switch (this.b) {
            case 1:
                StringBuilder sb = new StringBuilder();
                while (true) {
                    if (cVar.b()) {
                        char cA = cVar.a();
                        cVar.d++;
                        g(cA, sb);
                        if (sb.length() % 3 == 0) {
                            com.quizlet.shared.usecase.studiableMetadata.a.n(cVar, sb);
                            if (AbstractC3723t.f(cVar.a, cVar.d, 3) != 3) {
                                cVar.e = 0;
                            }
                        }
                    }
                }
                j(cVar, sb);
                break;
            default:
                super.c(cVar);
                break;
        }
    }

    @Override // com.quizlet.shared.usecase.studiableMetadata.a
    public final int g(char c, StringBuilder sb) {
        switch (this.b) {
            case 0:
                if (c == ' ') {
                    sb.append((char) 3);
                    return 1;
                }
                if (c >= '0' && c <= '9') {
                    sb.append((char) (c - ','));
                    return 1;
                }
                if (c >= 'a' && c <= 'z') {
                    sb.append((char) (c - 'S'));
                    return 1;
                }
                if (c < ' ') {
                    sb.append((char) 0);
                    sb.append(c);
                } else if (c >= '!' && c <= '/') {
                    sb.append((char) 1);
                    sb.append((char) (c - '!'));
                } else if (c >= ':' && c <= '@') {
                    sb.append((char) 1);
                    sb.append((char) (c - '+'));
                } else if (c >= '[' && c <= '_') {
                    sb.append((char) 1);
                    sb.append((char) (c - 'E'));
                } else if (c == '`') {
                    sb.append((char) 2);
                    sb.append((char) (c - '`'));
                } else if (c >= 'A' && c <= 'Z') {
                    sb.append((char) 2);
                    sb.append((char) (c - '@'));
                } else {
                    if (c < '{' || c > 127) {
                        sb.append("\u0001\u001e");
                        return g((char) (c - 128), sb) + 2;
                    }
                    sb.append((char) 2);
                    sb.append((char) (c - '`'));
                }
                return 2;
            default:
                if (c == '\r') {
                    sb.append((char) 0);
                } else if (c == ' ') {
                    sb.append((char) 3);
                } else if (c == '*') {
                    sb.append((char) 1);
                } else if (c == '>') {
                    sb.append((char) 2);
                } else if (c >= '0' && c <= '9') {
                    sb.append((char) (c - ','));
                } else {
                    if (c < 'A' || c > 'Z') {
                        AbstractC3723t.b(c);
                        throw null;
                    }
                    sb.append((char) (c - '3'));
                }
                return 1;
        }
    }

    @Override // com.quizlet.shared.usecase.studiableMetadata.a
    public final int i() {
        switch (this.b) {
            case 0:
                return 2;
            default:
                return 3;
        }
    }

    @Override // com.quizlet.shared.usecase.studiableMetadata.a
    public void j(c cVar, StringBuilder sb) {
        switch (this.b) {
            case 1:
                StringBuilder sb2 = cVar.c;
                cVar.c(sb2.length());
                int length = cVar.f.b - sb2.length();
                cVar.d -= sb.length();
                String str = cVar.a;
                if ((str.length() - cVar.g) - cVar.d > 1 || length > 1 || (str.length() - cVar.g) - cVar.d != length) {
                    cVar.d((char) 254);
                }
                if (cVar.e < 0) {
                    cVar.e = 0;
                    break;
                }
                break;
            default:
                super.j(cVar, sb);
                break;
        }
    }
}
