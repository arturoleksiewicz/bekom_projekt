package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/samochody")
public class SamochodController {

    @Autowired
    private SamochodRepository samochodRepository;

    @GetMapping
    public List<Samochod> getAllSamochody() {
        return samochodRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Samochod> getSamochodById(@PathVariable(value = "id") Long id) {
        return samochodRepository.findById(id)
                .map(samochod -> ResponseEntity.ok().body(samochod))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public Samochod createSamochod(@RequestBody Samochod samochod) {
        return samochodRepository.save(samochod);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Samochod> updateSamochod(@PathVariable(value = "id") Long id, @RequestBody Samochod samochodDetails) {
        return samochodRepository.findById(id)
                .map(samochod -> {
                    samochod.setMarka(samochodDetails.getMarka());
                    samochod.setModel(samochodDetails.getModel());
                    samochod.setRokProdukcji(samochodDetails.getRokProdukcji());
                    samochod.setCena(samochodDetails.getCena());
                    samochod.setDostepny(samochodDetails.getDostepny());
                    Samochod updatedSamochod = samochodRepository.save(samochod);
                    return ResponseEntity.ok().body(updatedSamochod);
                }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteSamochod(@PathVariable(value = "id") Long id) {
        return samochodRepository.findById(id)
                .map(samochod -> {
                    samochodRepository.delete(samochod);
                    return ResponseEntity.ok().build();
                }).orElse(ResponseEntity.notFound().build());
    }
}