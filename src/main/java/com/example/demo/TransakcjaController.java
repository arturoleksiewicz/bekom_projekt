package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/transakcje")
public class TransakcjaController {

    @Autowired
    private TransakcjaRepository transakcjaRepository;

    @GetMapping
    public List<Transakcja> getAllTransakcje() {
        return transakcjaRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Transakcja> getTransakcjaById(@PathVariable(value = "id") Long id) {
        return transakcjaRepository.findById(id)
                .map(transakcja -> ResponseEntity.ok().body(transakcja))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public Transakcja createTransakcja(@RequestBody Transakcja transakcja) {
        return transakcjaRepository.save(transakcja);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Transakcja> updateTransakcja(@PathVariable(value = "id") Long id, @RequestBody Transakcja transakcjaDetails) {
        return transakcjaRepository.findById(id)
                .map(transakcja -> {
                    transakcja.setKlient(transakcjaDetails.getKlient());
                    transakcja.setModel(transakcjaDetails.getModel());
                    transakcja.setData(transakcjaDetails.getData());
                    transakcja.setKwota(transakcjaDetails.getKwota());
                    Transakcja updatedTransakcja = transakcjaRepository.save(transakcja);
                    return ResponseEntity.ok().body(updatedTransakcja);
                }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteTransakcja(@PathVariable(value = "id") Long id) {
        return transakcjaRepository.findById(id)
                .map(transakcja -> {
                    transakcjaRepository.delete(transakcja);
                    return ResponseEntity.ok().build();
                }).orElse(ResponseEntity.notFound().build());
    }
}