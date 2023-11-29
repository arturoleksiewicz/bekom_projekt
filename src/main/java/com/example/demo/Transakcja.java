package com.example.demo;


import jakarta.persistence.*;
import jakarta.persistence.Id;
import java.math.BigDecimal;
import java.util.Date;

@Entity
public class Transakcja {
    public Long getId() {
        return id;
    }
    public Transakcja(){}
    public void setId(Long id) {
        this.id = id;
    }

    public Klient getKlient() {
        return klient;
    }

    public void setKlient(Klient klient) {
        this.klient = klient;
    }

    public Model getModel() {
        return model;
    }

    public void setModel(Model model) {
        this.model = model;
    }

    public Date getData() {
        return data;
    }

    public void setData(Date data) {
        this.data = data;
    }

    public BigDecimal getKwota() {
        return kwota;
    }

    public void setKwota(BigDecimal kwota) {
        this.kwota = kwota;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    public Transakcja(Long id, Klient klient, Model model, Date data, BigDecimal kwota) {
        this.id = id;
        this.klient = klient;
        this.model = model;
        this.data = data;
        this.kwota = kwota;
    }

    @ManyToOne
    @JoinColumn(name = "klient_id", nullable = false)
    private Klient klient;

    @ManyToOne
    @JoinColumn(name = "model_id", nullable = false)
    private Model model;

    private Date data;
    private BigDecimal kwota;

    // Gettery, settery, konstruktory
}